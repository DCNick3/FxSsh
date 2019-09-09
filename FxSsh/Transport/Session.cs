using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using FxSsh.Algorithms;
using FxSsh.Messages;
using FxSsh.Services;
using FxSsh.Services.Connection;
using FxSsh.Services.Userauth;
using FxSsh.Util;

namespace FxSsh.Transport
{
    /// <summary>
    /// Defines generic transport level
    /// </summary>
    public abstract class Session : IMessageHandler
    {
        private const byte CarriageReturn = 0x0d;
        private const byte LineFeed = 0x0a;
        internal const int MaximumSshPacketSize = LocalChannelDataPacketSize;
        internal const int InitialLocalWindowSize = LocalChannelDataPacketSize * 32;
        internal const int LocalChannelDataPacketSize = 1024 * 32;

        private static readonly RandomNumberGenerator Rng = new RNGCryptoServiceProvider();
        private static readonly Dictionary<byte, Type> MessagesMetadata;


        private readonly object _locker = new object();
        private readonly Socket _socket;
#if DEBUG
        private readonly TimeSpan _timeout = TimeSpan.FromDays(1);
#else
        private readonly TimeSpan _timeout = TimeSpan.FromSeconds(30);
#endif
        private readonly List<ISshService> _services = new List<ISshService>();

        private uint _outboundPacketSequence;
        private uint _inboundPacketSequence;
        private uint _outboundFlow;
        private uint _inboundFlow;
        private bool _disconnecting;
        private Algorithms _algorithms;
        protected ExchangeContext exchangeContext;
        private readonly ConcurrentQueue<Message> _blockedMessages = new ConcurrentQueue<Message>();
        private readonly EventWaitHandle _hasBlockedMessagesWaitHandle = new ManualResetEvent(true);

        public event EventHandler<ISshService> ServiceRegistered;

        public abstract SessionRole Role { get; }
        public string LocalVersion { get; }
        public string RemoteVersion { get; private set; }
        public byte[] SessionId { get; protected set; }

        public T GetService<T>() where T : ISshService
        {
            return (T) _services.FirstOrDefault(x => x is T);
        }

        static Session()
        {
            MessagesMetadata = (from t in typeof(Message).Assembly.GetTypes()
                    let attrib =
                        (MessageAttribute) t.GetCustomAttributes(typeof(MessageAttribute), false).FirstOrDefault()
                    where attrib != null
                    select new {attrib.Number, Type = t})
                .ToDictionary(x => x.Number, x => x.Type);
        }

        protected Session(Socket socket, string programVersion)
        {
            _socket = socket;
            LocalVersion = programVersion;
        }

        public event EventHandler<EventArgs> Disconnected;
        public event EventHandler<DetermineAlgorithmsArgs> DetermineAlgorithms;
        public event EventHandler<AlgorithmsDeterminedArgs> AlgorithmsDetermined;

        public void EstablishConnection()
        {
            if (!_socket.Connected) return;

            SetSocketOptions();

            SocketWriteProtocolVersion();
            RemoteVersion = SocketReadProtocolVersion();
            if (!Regex.IsMatch(RemoteVersion, "SSH-2.0-.+"))
                throw new SshConnectionException(
                    $"Unsupported SSH version {RemoteVersion}. This library supports SSH v2.0.",
                    DisconnectReason.ProtocolVersionNotSupported);

            ConsiderReExchange(true);

            try
            {
                while (_socket != null && _socket.Connected)
                {
                    var message = ReceiveMessage();
                    if (message is UnknownMessage unknownMessage)
                        SendMessage(unknownMessage.MakeUnimplementedMessage());
                    else
                        HandleMessageCore(message);
                }
            }
            finally
            {
                foreach (var service in _services) service.CloseService();
            }
        }

        public void Disconnect(DisconnectReason reason = DisconnectReason.ByApplication,
            string description = "Connection terminated by the server.")
        {
            if (!_disconnecting)
            {
                var message = new DisconnectMessage(reason, description);
                TrySendMessage(message);
            }

            try
            {
                _socket.Shutdown(SocketShutdown.Both);
                _socket.Close();
                _socket.Dispose();
            }
            catch
            {
                //TODO: Why?
            }

            Disconnected?.Invoke(this, EventArgs.Empty);
        }

        #region Socket operations

        private void SetSocketOptions()
        {
            const int socketBufferSize = 2 * MaximumSshPacketSize;
            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            _socket.LingerState = new LingerOption(false, 0);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, socketBufferSize);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, socketBufferSize);
            _socket.ReceiveTimeout = (int) _timeout.TotalMilliseconds;
        }

        private string SocketReadProtocolVersion()
        {
            // http://tools.ietf.org/html/rfc4253#section-4.2
            var buffer = new byte[255];
            var dummy = new byte[255];
            var pos = 0;

            while (pos < buffer.Length)
            {
                // TODO: rewrite using async/await
                var ar = _socket.BeginReceive(buffer, pos, buffer.Length - pos, SocketFlags.Peek, null, null);
                WaitHandle(ar);
                Debug.Assert(ar != null, nameof(ar) + " != null");
                var len = _socket.EndReceive(ar);

                if (len == 0)
                    throw new SshConnectionException("Couldn't read the protocol version",
                        DisconnectReason.ProtocolError);

                for (var i = 0; i < len; i++, pos++)
                    if (pos > 0 && buffer[pos - 1] == CarriageReturn && buffer[pos] == LineFeed)
                    {
                        _socket.Receive(dummy, 0, i + 1, SocketFlags.None);
                        return Encoding.ASCII.GetString(buffer, 0, pos - 1);
                    }

                _socket.Receive(dummy, 0, len, SocketFlags.None);
            }

            throw new SshConnectionException("Couldn't read the protocol version", DisconnectReason.ProtocolError);
        }

        private void SocketWriteProtocolVersion()
        {
            SocketWrite(Encoding.ASCII.GetBytes(LocalVersion + "\r\n"));
        }

        private byte[] SocketRead(int length)
        {
            var pos = 0;
            var buffer = new byte[length];

            var msSinceLastData = 0;

            while (pos < length)
                try
                {
                    var ar = _socket.BeginReceive(buffer, pos, length - pos, SocketFlags.None, null, null);
                    WaitHandle(ar);
                    Debug.Assert(ar != null, nameof(ar) + " != null");
                    var len = _socket.EndReceive(ar);
                    if (!_socket.Connected)
                        throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);

                    if (len == 0 && _socket.Available == 0)
                    {
                        if (msSinceLastData >= _timeout.TotalMilliseconds)
                            throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);

                        msSinceLastData += 50;
                        Thread.Sleep(50);
                    }
                    else
                    {
                        msSinceLastData = 0;
                    }

                    pos += len;
                }
                catch (SocketException exp)
                {
                    if (exp.SocketErrorCode == SocketError.WouldBlock ||
                        exp.SocketErrorCode == SocketError.IOPending ||
                        exp.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                        Thread.Sleep(30);
                    else
                        throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                }

            return buffer;
        }

        private void SocketWrite(byte[] data)
        {
            var pos = 0;
            var length = data.Length;

            while (pos < length)
                try
                {
                    var ar = _socket.BeginSend(data, pos, length - pos, SocketFlags.None, null, null);
                    WaitHandle(ar);
                    Debug.Assert(ar != null, nameof(ar) + " != null");
                    pos += _socket.EndSend(ar);
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.WouldBlock ||
                        ex.SocketErrorCode == SocketError.IOPending ||
                        ex.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                        Thread.Sleep(30);
                    else
                        throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                }
        }

        private void WaitHandle(IAsyncResult ar)
        {
            if (!ar.AsyncWaitHandle.WaitOne(_timeout))
                throw new SshConnectionException(
                    $"Socket operation has timed out after {_timeout.TotalMilliseconds:F0} milliseconds.",
                    DisconnectReason.ConnectionLost);
        }

        #endregion

        #region Message operations

        private Message ReceiveMessage()
        {
            var useAlg = _algorithms != null;

            var blockSize = (byte) (useAlg ? Math.Max(8, _algorithms.ReceiveEncryption.BlockBytesSize) : 8);
            var firstBlock = SocketRead(blockSize);
            if (useAlg)
                firstBlock = _algorithms.ReceiveEncryption.Transform(firstBlock);

            var packetLength = (firstBlock[0] << 24) | (firstBlock[1] << 16) | (firstBlock[2] << 8) | firstBlock[3];
            var paddingLength = firstBlock[4];
            var bytesToRead = packetLength - blockSize + 4;

            var followingBlocks = SocketRead(bytesToRead);
            if (useAlg)
                followingBlocks = _algorithms.ReceiveEncryption.Transform(followingBlocks);

            var fullPacket = firstBlock.Concat(followingBlocks).ToArray();
            var data = fullPacket.Skip(5).Take(packetLength - paddingLength - 1).ToArray();
            if (useAlg)
            {
                var remoteMac = SocketRead(_algorithms.ReceiveHmac.DigestLength);
                var mac = ComputeHmac(_algorithms.ReceiveHmac, fullPacket, _inboundPacketSequence);
                if (!remoteMac.SequenceEqual(mac))
                    throw new SshConnectionException("Invalid MAC", DisconnectReason.MacError);

                data = _algorithms.ReceiveCompression.Decompress(data);
            }

            var typeNumber = data[0];
            var group = Message.GetGroup(typeNumber);
            Message message;

            if (group == Message.Group.UserauthMethodSpecific)
            {
                var userauthService = GetService<UserauthService>();
                if (userauthService == null)
                    throw new SshConnectionException("Userauth method-specific message received, but " +
                                                     "userauth service is not registered",
                        DisconnectReason.ProtocolError);
                message = userauthService.CreateMethodSpecificMessage(typeNumber);
            }
            else
            {
                var implemented = MessagesMetadata.ContainsKey(typeNumber);
                message = implemented
                    ? (Message) Activator.CreateInstance(MessagesMetadata[typeNumber])
                    : new UnknownMessage {SequenceNumber = _inboundPacketSequence, UnknownMessageType = typeNumber};
            }

            if (!(message is UnknownMessage))
                message.LoadPacket(data);

            lock (_locker)
            {
                _inboundPacketSequence++;
                _inboundFlow += (uint) packetLength;
            }

            ConsiderReExchange();

            return message;
        }

        internal void SendMessage(Message message)
        {
            if (exchangeContext != null
                && message.MessageType > 4 && (message.MessageType < 20 || message.MessageType > 49))
            {
                _blockedMessages.Enqueue(message);
                return;
            }

            _hasBlockedMessagesWaitHandle.WaitOne();
            lock (_locker)
            {
                SendMessageInternal(message);
            }
        }

        private void SendMessageInternal(Message message)
        {
            var useAlg = _algorithms != null;

            var blockSize = (byte) (useAlg ? Math.Max(8, _algorithms.TransmitEncryption.BlockBytesSize) : 8);
            var payload = message.SerializePacket();
            if (useAlg)
                payload = _algorithms.TransmitCompression.Compress(payload);

            // http://tools.ietf.org/html/rfc4253
            // 6.  Binary Packet Protocol
            // the total length of (packet_length || padding_length || payload || padding)
            // is a multiple of the cipher block size or 8,
            // padding length must between 4 and 255 bytes.
            var paddingLength = (byte) (blockSize - (payload.Length + 5) % blockSize);
            if (paddingLength < 4)
                paddingLength += blockSize;

            var packetLength = (uint) payload.Length + paddingLength + 1;

            var padding = new byte[paddingLength];
            Rng.GetBytes(padding);

            using (var worker = new SshDataWorker())
            {
                worker.Write(packetLength);
                worker.Write(paddingLength);
                worker.WriteRawBytes(payload);
                worker.WriteRawBytes(padding);

                payload = worker.ToByteArray();
            }

            if (useAlg)
            {
                var mac = ComputeHmac(_algorithms.TransmitHmac, payload, _outboundPacketSequence);
                payload = _algorithms.TransmitEncryption.Transform(payload).Concat(mac).ToArray();
            }

            SocketWrite(payload);

            lock (_locker)
            {
                _outboundPacketSequence++;
                _outboundFlow += packetLength;
            }

            ConsiderReExchange();
        }

        private void ConsiderReExchange(bool force = false)
        {
            var kex = false;
            lock (_locker)
            {
                if (exchangeContext == null
                    && (force || _inboundFlow + _outboundFlow > 1024 * 1024 * 512)) // 0.5 GiB
                {
                    exchangeContext = new ExchangeContext();
                    kex = true;
                }
            }

            if (kex)
            {
                var kexInitMessage = LoadKexInitMessage();
                if (Role == SessionRole.Server)
                    exchangeContext.ServerKexInitPayload = kexInitMessage.SerializePacket();
                else
                    exchangeContext.ClientKexInitPayload = kexInitMessage.SerializePacket();

                SendMessage(kexInitMessage);
            }
        }

        private void ContinueSendBlockedMessages()
        {
            if (_blockedMessages.Count > 0)
                while (_blockedMessages.TryDequeue(out var message))
                    SendMessageInternal(message);
        }

        private void TrySendMessage(Message message)
        {
            // Ewwww... Catching ALL exceptions is bad.
            // TODO: Look into changing this and similar places to better error handling
            try
            {
                SendMessage(message);
            }
            catch
            {
                // Ignore
            }
        }

        protected virtual KeyExchangeInitMessage LoadKexInitMessage()
        {
            // be VERY attentive, when editing this. Algorithm names are strings, though no static checks for you
            var message = new KeyExchangeInitMessage();
            var determineAlgorithmsArgs = new DetermineAlgorithmsArgs
            {
                ServerHostKeyAlgorithms = CryptoAlgorithms.PublicKeyAlgorithms.Keys.ToArray(),
                KeyExchangeAlgorithms = CryptoAlgorithms.KeyExchangeAlgorithms.Keys.ToArray(),

                EncryptionAlgorithmsClientToServer = CryptoAlgorithms.EncryptionAlgorithms.Keys.ToArray(),
                EncryptionAlgorithmsServerToClient = CryptoAlgorithms.EncryptionAlgorithms.Keys.ToArray(),
                MacAlgorithmsClientToServer = CryptoAlgorithms.HmacAlgorithms.Keys.ToArray(),
                MacAlgorithmsServerToClient = CryptoAlgorithms.HmacAlgorithms.Keys.ToArray(),
                CompressionAlgorithmsClientToServer = CryptoAlgorithms.CompressionAlgorithms.Keys.ToArray(),
                CompressionAlgorithmsServerToClient = CryptoAlgorithms.CompressionAlgorithms.Keys.ToArray()
            };
            // To allow user to ban weak algorithms
            DetermineAlgorithms?.Invoke(this, determineAlgorithmsArgs);

            message.KeyExchangeAlgorithms = determineAlgorithmsArgs.KeyExchangeAlgorithms;
            message.ServerHostKeyAlgorithms = determineAlgorithmsArgs.ServerHostKeyAlgorithms;

            message.EncryptionAlgorithmsClientToServer = determineAlgorithmsArgs.EncryptionAlgorithmsClientToServer;
            message.EncryptionAlgorithmsServerToClient = determineAlgorithmsArgs.EncryptionAlgorithmsServerToClient;
            message.MacAlgorithmsClientToServer = determineAlgorithmsArgs.MacAlgorithmsClientToServer;
            message.MacAlgorithmsServerToClient = determineAlgorithmsArgs.MacAlgorithmsServerToClient;
            message.CompressionAlgorithmsServerToClient = determineAlgorithmsArgs.CompressionAlgorithmsServerToClient;
            message.CompressionAlgorithmsClientToServer = determineAlgorithmsArgs.CompressionAlgorithmsClientToServer;

            /* TODO: Language stuff is not currently implemented. */
            message.LanguagesClientToServer = new[] {""};
            message.LanguagesServerToClient = new[] {""};
            message.FirstKexPacketFollows = false;
            message.Reserved = 0;


            return message;
        }

        #endregion

        #region Handle messages

        private void HandleMessageCore(Message message)
        {
            this.InvokeHandleMessage(message);
        }

        // ReSharper disable once UnusedMember.Global
        protected void HandleMessage(DisconnectMessage message)
        {
            _disconnecting = true;
            Disconnect(message.ReasonCode, message.Description);
        }

        // ReSharper disable once UnusedMember.Global
        protected void HandleMessage(KeyExchangeInitMessage message)
        {
            ConsiderReExchange(true);

            var ourMessage = LoadKexInitMessage();

            exchangeContext.KeyExchange =
                ChooseAlgorithm(ourMessage.KeyExchangeAlgorithms, message.KeyExchangeAlgorithms);
            exchangeContext.ServerIdentification =
                ChooseAlgorithm(ourMessage.ServerHostKeyAlgorithms, message.ServerHostKeyAlgorithms);


            var clientToServerEncryption = ChooseAlgorithm(ourMessage.EncryptionAlgorithmsClientToServer,
                message.EncryptionAlgorithmsClientToServer);
            var serverToClientEncryption = ChooseAlgorithm(ourMessage.EncryptionAlgorithmsServerToClient,
                message.EncryptionAlgorithmsServerToClient);
            var clientToServerHmac =
                ChooseAlgorithm(ourMessage.MacAlgorithmsClientToServer, message.MacAlgorithmsClientToServer);
            var serverToClientHmac =
                ChooseAlgorithm(ourMessage.MacAlgorithmsServerToClient, message.MacAlgorithmsServerToClient);
            var clientToServerCompression = ChooseAlgorithm(ourMessage.CompressionAlgorithmsClientToServer,
                message.CompressionAlgorithmsClientToServer);
            var serverToClientCompression = ChooseAlgorithm(ourMessage.CompressionAlgorithmsServerToClient,
                message.CompressionAlgorithmsServerToClient);

            if (Role == SessionRole.Server)
            {
                exchangeContext.ReceiveEncryption = clientToServerEncryption;
                exchangeContext.TransmitEncryption = serverToClientEncryption;
                exchangeContext.ReceiveHmac = clientToServerHmac;
                exchangeContext.TransmitHmac = serverToClientHmac;
                exchangeContext.ReceiveCompression = clientToServerCompression;
                exchangeContext.TransmitCompression = serverToClientCompression;
            }
            else
            {
                exchangeContext.ReceiveEncryption = serverToClientEncryption;
                exchangeContext.TransmitEncryption = clientToServerEncryption;
                exchangeContext.ReceiveHmac = serverToClientHmac;
                exchangeContext.TransmitHmac = clientToServerHmac;
                exchangeContext.ReceiveCompression = serverToClientCompression;
                exchangeContext.TransmitCompression = clientToServerCompression;
            }

            AlgorithmsDetermined?.Invoke(this, new AlgorithmsDeterminedArgs
            {
                KeyExchange = exchangeContext.KeyExchange,
                PublicKey = exchangeContext.ServerIdentification,
                
                ReceiveEncryption = exchangeContext.ReceiveEncryption,
                TransmitEncryption = exchangeContext.TransmitEncryption,
                ReceiveHmac = exchangeContext.ReceiveHmac,
                TransmitHmac = exchangeContext.TransmitHmac,
                ReceiveCompression = exchangeContext.ReceiveCompression,
                TransmitCompression = exchangeContext.TransmitCompression,
            });

            if (Role == SessionRole.Server)
                exchangeContext.ClientKexInitPayload = message.SerializePacket();
            else
                exchangeContext.ServerKexInitPayload = message.SerializePacket();

            DoExchange();
        }

        // ReSharper disable once UnusedMember.Global
        protected void HandleMessage(NewKeysMessage message)
        {
            _hasBlockedMessagesWaitHandle.Reset();

            lock (_locker)
            {
                _inboundFlow = 0;
                _outboundFlow = 0;
                _algorithms = exchangeContext.NewAlgorithms;
                exchangeContext = null;
            }

            ContinueSendBlockedMessages();
            _hasBlockedMessagesWaitHandle.Set();
        }

        protected void HandleMessage(UserauthServiceMessage message)
        {
            var service = GetService<UserauthService>();
            if (service == null)
                SendMessage(new UnimplementedMessage { SequenceNumber = _inboundPacketSequence });
            else
                service?.HandleMessageCore(message);
        }

        protected void HandleMessage(ConnectionServiceMessage message)
        {
            var service = GetService<ConnectionService>();
            if (service == null)
                SendMessage(new UnimplementedMessage { SequenceNumber = _inboundPacketSequence });
            else
                service?.HandleMessageCore(message);
        }

        protected void HandleMessage(UnimplementedMessage message)
        {
        }

        #endregion

        protected abstract void DoExchange();

        internal void RegisterService(ISshService service)
        {
            ServiceRegistered?.Invoke(this, service);

            _services.Add(service);
        }

        private string ChooseAlgorithm(string[] localAlgorithms, string[] remoteAlgorithms)
        {
            string[] serverAlgorithms, clientAlgorithms;
            if (Role == SessionRole.Server)
            {
                serverAlgorithms = localAlgorithms;
                clientAlgorithms = remoteAlgorithms;
            }
            else
            {
                clientAlgorithms = localAlgorithms;
                serverAlgorithms = remoteAlgorithms;
            }

            foreach (var client in clientAlgorithms)
            foreach (var server in serverAlgorithms)
                if (client == server)
                    return client;

            throw new SshConnectionException("Failed to negotiate algorithm.", DisconnectReason.KeyExchangeFailed);
        }

        protected byte[] ComputeExchangeHash(KeyExchangeAlgorithm keyExchangeAlg, byte[] hostKeyAndCerts, byte[] clientExchangeValue,
            byte[] serverExchangeValue, byte[] sharedSecret)
        {
            using (var worker = new SshDataWorker())
            {
                if (Role == SessionRole.Server)
                {
                    worker.Write(RemoteVersion, Encoding.ASCII);
                    worker.Write(LocalVersion, Encoding.ASCII);
                }
                else
                {
                    worker.Write(LocalVersion, Encoding.ASCII);
                    worker.Write(RemoteVersion, Encoding.ASCII);
                }

                worker.Write(exchangeContext.ClientKexInitPayload);
                worker.Write(exchangeContext.ServerKexInitPayload);
                worker.Write(hostKeyAndCerts);
                worker.WriteMpint(clientExchangeValue);
                worker.WriteMpint(serverExchangeValue);
                worker.WriteMpint(sharedSecret);

                return keyExchangeAlg.ComputeHash(worker.ToByteArray());
            }
        }

        protected byte[] ComputeEncryptionKey(KeyExchangeAlgorithm keyExchangeAlg, byte[] exchangeHash, int blockSize,
            byte[] sharedSecret, char letter)
        {
            var keyBuffer = new byte[blockSize];
            var keyBufferIndex = 0;
            byte[] currentHash = null;

            while (keyBufferIndex < blockSize)
            {
                using (var worker = new SshDataWorker())
                {
                    worker.WriteMpint(sharedSecret);
                    worker.WriteRawBytes(exchangeHash);

                    if (currentHash == null)
                    {
                        worker.Write((byte) letter);
                        worker.WriteRawBytes(SessionId);
                    }
                    else
                    {
                        worker.WriteRawBytes(currentHash);
                    }

                    currentHash = keyExchangeAlg.ComputeHash(worker.ToByteArray());
                }

                var currentHashLength = Math.Min(currentHash.Length, blockSize - keyBufferIndex);
                Array.Copy(currentHash, 0, keyBuffer, keyBufferIndex, currentHashLength);

                keyBufferIndex += currentHashLength;
            }

            return keyBuffer;
        }

        private byte[] ComputeHmac(HmacAlgorithm alg, byte[] payload, uint seq)
        {
            using (var worker = new SshDataWorker())
            {
                worker.Write(seq);
                worker.WriteRawBytes(payload);

                return alg.ComputeHash(worker.ToByteArray());
            }
        }

        protected class Algorithms
        {
            public KeyExchangeAlgorithm KeyExchange;
            public CompressionAlgorithm ReceiveCompression;
            public EncryptionAlgorithm ReceiveEncryption;
            public HmacAlgorithm ReceiveHmac;
            public PublicKeyAlgorithm ServerIdentification;
            public CompressionAlgorithm TransmitCompression;
            public EncryptionAlgorithm TransmitEncryption;
            public HmacAlgorithm TransmitHmac;
        }

        /// <summary>
        /// Specifies algorithms selected as a result of key exchange.
        /// </summary>
        protected class ExchangeContext
        {
            public byte[] ClientKexInitPayload;
            public string KeyExchange;

            public Algorithms NewAlgorithms;
            public string ServerIdentification;
            public string ReceiveCompression;
            public string ReceiveEncryption;
            public string ReceiveHmac;

            public byte[] ServerKexInitPayload;
            public string TransmitCompression;
            public string TransmitEncryption;
            public string TransmitHmac;
        }
    }
}