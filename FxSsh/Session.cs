using FxSsh.Algorithms;
using FxSsh.Messages;
using FxSsh.Services;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace FxSsh
{
    public abstract class Session : IDynamicInvoker
    {
        private const byte CarriageReturn = 0x0d;
        private const byte LineFeed = 0x0a;
        internal const int MaximumSshPacketSize = LocalChannelDataPacketSize;
        internal const int InitialLocalWindowSize = LocalChannelDataPacketSize * 32;
        internal const int LocalChannelDataPacketSize = 1024 * 32;

        private static readonly RandomNumberGenerator _rng = new RNGCryptoServiceProvider();
        private static readonly Dictionary<byte, Type> _messagesMetadata;
        internal static readonly Dictionary<string, Func<KexAlgorithm>> _keyExchangeAlgorithms =
            new Dictionary<string, Func<KexAlgorithm>>();
        
        internal static readonly
            Dictionary<string, (Func<byte[], PublicKeyAlgorithm> FromCspBlob, Func<byte[], PublicKeyAlgorithm>
                FromKeyAndCertificatesData)> _publicKeyAlgorithms =
                new Dictionary<string, (Func<byte[], PublicKeyAlgorithm>, Func<byte[], PublicKeyAlgorithm>)>();
        
        internal static readonly Dictionary<string, Func<CipherInfo>> _encryptionAlgorithms =
            new Dictionary<string, Func<CipherInfo>>();
        internal static readonly Dictionary<string, Func<HmacInfo>> _hmacAlgorithms =
            new Dictionary<string, Func<HmacInfo>>();
        internal static readonly Dictionary<string, Func<CompressionAlgorithm>> _compressionAlgorithms =
            new Dictionary<string, Func<CompressionAlgorithm>>();

        private readonly object _locker = new object();
        private readonly Socket _socket;
#if DEBUG
        private readonly TimeSpan _timeout = TimeSpan.FromDays(1);
#else
        private readonly TimeSpan _timeout = TimeSpan.FromSeconds(30);
#endif
        protected readonly List<SshService> _services = new List<SshService>();

        private uint _outboundPacketSequence;
        private uint _inboundPacketSequence;
        private uint _outboundFlow;
        private uint _inboundFlow;
        private bool _disconnecting = false;
        private Algorithms _algorithms = null;
        protected ExchangeContext _exchangeContext = null;
        private readonly ConcurrentQueue<Message> _blockedMessages = new ConcurrentQueue<Message>();
        private readonly EventWaitHandle _hasBlockedMessagesWaitHandle = new ManualResetEvent(true);

        public abstract SessionRole Role { get; }
        public string LocalVersion { get; private set; }
        public string RemoteVersion { get; private set; }
        public byte[] SessionId { get; protected set; }

        public T GetService<T>() where T : SshService
        {
            return (T)_services.FirstOrDefault(x => x is T);
        }
        
        static Session()
        {
            _keyExchangeAlgorithms.Add("diffie-hellman-group14-sha1", () => new DiffieHellmanGroupSha1(new DiffieHellman(2048)));
            _keyExchangeAlgorithms.Add("diffie-hellman-group1-sha1", () => new DiffieHellmanGroupSha1(new DiffieHellman(1024)));
    
            _publicKeyAlgorithms.Add("ssh-rsa", (x => new RsaKey().ImportInternalBlob(x), x => new RsaKey().ImportKeyAndCertificatesData(x)));
            _publicKeyAlgorithms.Add("ssh-dss", (x => new DssKey().ImportInternalBlob(x), x => new DssKey().ImportKeyAndCertificatesData(x)));
            _publicKeyAlgorithms.Add("ssh-ed25519", (x => new Ed25519Key().ImportInternalBlob(x), x => new Ed25519Key().ImportKeyAndCertificatesData(x)));

            _encryptionAlgorithms.Add("aes128-ctr", () => new CipherInfo(new AesCryptoServiceProvider(), 128, CipherModeEx.CTR));
            _encryptionAlgorithms.Add("aes192-ctr", () => new CipherInfo(new AesCryptoServiceProvider(), 192, CipherModeEx.CTR));
            _encryptionAlgorithms.Add("aes256-ctr", () => new CipherInfo(new AesCryptoServiceProvider(), 256, CipherModeEx.CTR));
            _encryptionAlgorithms.Add("aes128-cbc", () => new CipherInfo(new AesCryptoServiceProvider(), 128, CipherModeEx.CBC));
            _encryptionAlgorithms.Add("3des-cbc", () => new CipherInfo(new TripleDESCryptoServiceProvider(), 192, CipherModeEx.CBC));
            _encryptionAlgorithms.Add("aes192-cbc", () => new CipherInfo(new AesCryptoServiceProvider(), 192, CipherModeEx.CBC));
            _encryptionAlgorithms.Add("aes256-cbc", () => new CipherInfo(new AesCryptoServiceProvider(), 256, CipherModeEx.CBC));

            _hmacAlgorithms.Add("hmac-md5", () => new HmacInfo(new HMACMD5(), 128));
            _hmacAlgorithms.Add("hmac-sha1", () => new HmacInfo(new HMACSHA1(), 160));

            _compressionAlgorithms.Add("none", () => new NoCompression());

            _messagesMetadata = (from t in typeof(Message).Assembly.GetTypes()
                                 let attrib = (MessageAttribute)t.GetCustomAttributes(typeof(MessageAttribute), false).FirstOrDefault()
                                 where attrib != null
                                 select new { attrib.Number, Type = t })
                                 .ToDictionary(x => x.Number, x => x.Type);
        }

        public Session(Socket socket, string programVersion)
        {
            Contract.Requires(socket != null);
            Contract.Requires(programVersion != null);

            _socket = socket;
            LocalVersion = programVersion;
        }

        public event EventHandler<EventArgs> Disconnected;

        public event EventHandler<KeyExchangeArgs> KeysExchanged;

        public void EstablishConnection()
        {
            if (!_socket.Connected)
            {
                return;
            }

            SetSocketOptions();

            SocketWriteProtocolVersion();
            RemoteVersion = SocketReadProtocolVersion();
            if (!Regex.IsMatch(RemoteVersion, "SSH-2.0-.+"))
            {
                throw new SshConnectionException(
                    string.Format("Not supported SSH version {0}. This library supports SSH v2.0.", RemoteVersion),
                    DisconnectReason.ProtocolVersionNotSupported);
            }

            ConsiderReExchange(true);

            try
            {
                while (_socket != null && _socket.Connected)
                {
                    var message = ReceiveMessage();
                    if (message is UnknownMessage)
                        SendMessage((message as UnknownMessage).MakeUnimplementedMessage());
                    else
                        HandleMessageCore(message);
                }
            }
            finally
            {
                foreach (var service in _services)
                {
                    service.CloseService();
                }
            }
        }

        public void Disconnect(DisconnectReason reason = DisconnectReason.ByApplication, string description = "Connection terminated by the server.")
        {
            Contract.Requires(description != null);
            
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
            catch { }

            Disconnected?.Invoke(this, EventArgs.Empty);
        }

        #region Socket operations
        private void SetSocketOptions()
        {
            const int socketBufferSize = 2 * MaximumSshPacketSize;
            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            _socket.LingerState = new LingerOption(enable: false, seconds: 0);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, socketBufferSize);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, socketBufferSize);
            _socket.ReceiveTimeout = (int)_timeout.TotalMilliseconds;
        }

        private string SocketReadProtocolVersion()
        {
            // http://tools.ietf.org/html/rfc4253#section-4.2
            var buffer = new byte[255];
            var dummy = new byte[255];
            var pos = 0;
            var len = 0;

            while (pos < buffer.Length)
            {
                var ar = _socket.BeginReceive(buffer, pos, buffer.Length - pos, SocketFlags.Peek, null, null);
                WaitHandle(ar);
                len = _socket.EndReceive(ar);

                if (len == 0)
                {
                    throw new SshConnectionException("Could't read the protocal version", DisconnectReason.ProtocolError);
                }

                for (var i = 0; i < len; i++, pos++)
                {
                    if (pos > 0 && buffer[pos - 1] == CarriageReturn && buffer[pos] == LineFeed)
                    {
                        _socket.Receive(dummy, 0, i + 1, SocketFlags.None);
                        return Encoding.ASCII.GetString(buffer, 0, pos - 1);
                    }
                }
                _socket.Receive(dummy, 0, len, SocketFlags.None);
            }
            throw new SshConnectionException("Could't read the protocal version", DisconnectReason.ProtocolError);
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
            {
                try
                {
                    var ar = _socket.BeginReceive(buffer, pos, length - pos, SocketFlags.None, null, null);
                    WaitHandle(ar);
                    var len = _socket.EndReceive(ar);
                    if (!_socket.Connected)
                    {
                        throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                    }

                    if (len == 0 && _socket.Available == 0)
                    {
                        if (msSinceLastData >= _timeout.TotalMilliseconds)
                        {
                            throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                        }

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
                    {
                        Thread.Sleep(30);
                    }
                    else
                        throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                }
            }

            return buffer;
        }

        private void SocketWrite(byte[] data)
        {
            var pos = 0;
            var length = data.Length;

            while (pos < length)
            {
                try
                {
                    var ar = _socket.BeginSend(data, pos, length - pos, SocketFlags.None, null, null);
                    WaitHandle(ar);
                    pos += _socket.EndSend(ar);
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.WouldBlock ||
                        ex.SocketErrorCode == SocketError.IOPending ||
                        ex.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                    {
                        Thread.Sleep(30);
                    }
                    else
                        throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                }
            }
        }

        private void WaitHandle(IAsyncResult ar)
        {
            if (!ar.AsyncWaitHandle.WaitOne(_timeout))
                throw new SshConnectionException(string.Format("Socket operation has timed out after {0:F0} milliseconds.",
                    _timeout.TotalMilliseconds),
                    DisconnectReason.ConnectionLost);
        }
        #endregion

        #region Message operations
        private Message ReceiveMessage()
        {
            var useAlg = _algorithms != null;

            var blockSize = (byte)(useAlg ? Math.Max(8, _algorithms.ReceiveEncryption.BlockBytesSize) : 8);
            var firstBlock = SocketRead(blockSize);
            if (useAlg)
                firstBlock = _algorithms.ReceiveEncryption.Transform(firstBlock);

            var packetLength = firstBlock[0] << 24 | firstBlock[1] << 16 | firstBlock[2] << 8 | firstBlock[3];
            var paddingLength = firstBlock[4];
            var bytesToRead = packetLength - blockSize + 4;

            var followingBlocks = SocketRead(bytesToRead);
            if (useAlg)
                followingBlocks = _algorithms.ReceiveEncryption.Transform(followingBlocks);

            var fullPacket = firstBlock.Concat(followingBlocks).ToArray();
            var data = fullPacket.Skip(5).Take(packetLength - paddingLength).ToArray();
            if (useAlg)
            {
                var clientMac = SocketRead(_algorithms.ReceiveHmac.DigestLength);
                var mac = ComputeHmac(_algorithms.ReceiveHmac, fullPacket, _inboundPacketSequence);
                if (!clientMac.SequenceEqual(mac))
                {
                    throw new SshConnectionException("Invalid MAC", DisconnectReason.MacError);
                }

                data = _algorithms.ReceiveCompression.Decompress(data);
            }

            var typeNumber = data[0];
            var implemented = _messagesMetadata.ContainsKey(typeNumber);
            var message = implemented
                ? (Message)Activator.CreateInstance(_messagesMetadata[typeNumber])
                : new UnknownMessage { SequenceNumber = _inboundPacketSequence, UnknownMessageType = typeNumber };

            if (implemented)
                message.LoadPacket(data);

            lock (_locker)
            {
                _inboundPacketSequence++;
                _inboundFlow += (uint)packetLength;
            }

            ConsiderReExchange();

            return message;
        }

        internal void SendMessage(Message message)
        {
            Contract.Requires(message != null);

            if (_exchangeContext != null
                && message.MessageType > 4 && (message.MessageType < 20 || message.MessageType > 49))
            {
                _blockedMessages.Enqueue(message);
                return;
            }

            _hasBlockedMessagesWaitHandle.WaitOne();
            lock (_locker)
                SendMessageInternal(message);
        }

        private void SendMessageInternal(Message message)
        {
            var useAlg = _algorithms != null;

            var blockSize = (byte)(useAlg ? Math.Max(8, _algorithms.TransmitEncryption.BlockBytesSize) : 8);
            var payload = message.SerializePacket();
            if (useAlg)
                payload = _algorithms.TransmitCompression.Compress(payload);

            // http://tools.ietf.org/html/rfc4253
            // 6.  Binary Packet Protocol
            // the total length of (packet_length || padding_length || payload || padding)
            // is a multiple of the cipher block size or 8,
            // padding length must between 4 and 255 bytes.
            var paddingLength = (byte)(blockSize - (payload.Length + 5) % blockSize);
            if (paddingLength < 4)
                paddingLength += blockSize;

            var packetLength = (uint)payload.Length + paddingLength + 1;

            var padding = new byte[paddingLength];
            _rng.GetBytes(padding);

            using (var worker = new SshDataWorker())
            {
                worker.Write(packetLength);
                worker.Write(paddingLength);
                worker.Write(payload);
                worker.Write(padding);

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
                if (_exchangeContext == null
                    && (force || _inboundFlow + _outboundFlow > 1024 * 1024 * 512)) // 0.5 GiB
                {
                    _exchangeContext = new ExchangeContext();
                    kex = true;
                }

            if (kex)
            {
                var kexInitMessage = LoadKexInitMessage();
                if (Role == SessionRole.Server)
                    _exchangeContext.ServerKexInitPayload = kexInitMessage.SerializePacket();
                else
                    _exchangeContext.ClientKexInitPayload = kexInitMessage.SerializePacket();

                SendMessage(kexInitMessage);
            }
        }

        private void ContinueSendBlockedMessages()
        {
            if (_blockedMessages.Count > 0)
            {
                Message message;
                while (_blockedMessages.TryDequeue(out message))
                {
                    SendMessageInternal(message);
                }
            }
        }

        internal bool TrySendMessage(Message message)
        {
            Contract.Requires(message != null);

            try
            {
                SendMessage(message);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private Message LoadKexInitMessage()
        {
            var message = new KeyExchangeInitMessage();
            message.KeyExchangeAlgorithms = _keyExchangeAlgorithms.Keys.ToArray();
            message.ServerHostKeyAlgorithms = _publicKeyAlgorithms.Keys.ToArray();
            
            message.EncryptionAlgorithmsClientToServer = _encryptionAlgorithms.Keys.ToArray();
            message.EncryptionAlgorithmsServerToClient = _encryptionAlgorithms.Keys.ToArray();
            message.MacAlgorithmsClientToServer = _hmacAlgorithms.Keys.ToArray();
            message.MacAlgorithmsServerToClient = _hmacAlgorithms.Keys.ToArray();
            message.CompressionAlgorithmsClientToServer = _compressionAlgorithms.Keys.ToArray();
            message.CompressionAlgorithmsServerToClient = _compressionAlgorithms.Keys.ToArray();
            
            message.LanguagesClientToServer = new[] { "" };
            message.LanguagesServerToClient = new[] { "" };
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

        protected void HandleMessage(DisconnectMessage message)
        {
            _disconnecting = true;
            Disconnect(message.ReasonCode, message.Description);
        }

        protected void HandleMessage(KeyExchangeInitMessage message)
        {
            ConsiderReExchange(true);

            KeysExchanged?.Invoke(this, new KeyExchangeArgs(this)
            {
                CompressionAlgorithmsClientToServer = message.CompressionAlgorithmsClientToServer,
                CompressionAlgorithmsServerToClient = message.CompressionAlgorithmsServerToClient,
                EncryptionAlgorithmsClientToServer = message.EncryptionAlgorithmsClientToServer,
                EncryptionAlgorithmsServerToClient = message.EncryptionAlgorithmsServerToClient,
                KeyExchangeAlgorithms = message.KeyExchangeAlgorithms,
                LanguagesClientToServer = message.LanguagesClientToServer,
                LanguagesServerToClient = message.LanguagesServerToClient,
                MacAlgorithmsClientToServer = message.MacAlgorithmsClientToServer,
                MacAlgorithmsServerToClient = message.MacAlgorithmsServerToClient,
                ServerHostKeyAlgorithms = message.ServerHostKeyAlgorithms
            });

            _exchangeContext.KeyExchange = ChooseAlgorithm(_keyExchangeAlgorithms.Keys.ToArray(), message.KeyExchangeAlgorithms);
            _exchangeContext.PublicKey = ChooseAlgorithm(_publicKeyAlgorithms.Keys.ToArray(), message.ServerHostKeyAlgorithms);
            
            
            var clientToServerEncryption = ChooseAlgorithm(_encryptionAlgorithms.Keys.ToArray(), message.EncryptionAlgorithmsClientToServer);
            var serverToClientEncryption = ChooseAlgorithm(_encryptionAlgorithms.Keys.ToArray(), message.EncryptionAlgorithmsServerToClient);
            var clientToServerHmac = ChooseAlgorithm(_hmacAlgorithms.Keys.ToArray(), message.MacAlgorithmsClientToServer);
            var serverToClientHmac = ChooseAlgorithm(_hmacAlgorithms.Keys.ToArray(), message.MacAlgorithmsServerToClient);
            var clientToServerCompression = ChooseAlgorithm(_compressionAlgorithms.Keys.ToArray(), message.CompressionAlgorithmsClientToServer);
            var serverToClientCompression = ChooseAlgorithm(_compressionAlgorithms.Keys.ToArray(), message.CompressionAlgorithmsServerToClient);

            if (Role == SessionRole.Server)
            {
                _exchangeContext.ReceiveEncryption = clientToServerEncryption;
                _exchangeContext.TransmitEncryption = serverToClientEncryption;
                _exchangeContext.ReceiveHmac = clientToServerHmac;
                _exchangeContext.TransmitHmac = serverToClientHmac;
                _exchangeContext.ReceiveCompression = clientToServerCompression;
                _exchangeContext.TransmitCompression = serverToClientCompression;
            }
            else
            {
                _exchangeContext.ReceiveEncryption = serverToClientEncryption;
                _exchangeContext.TransmitEncryption = clientToServerEncryption;
                _exchangeContext.ReceiveHmac = serverToClientHmac;
                _exchangeContext.TransmitHmac = clientToServerHmac;
                _exchangeContext.ReceiveCompression = serverToClientCompression;
                _exchangeContext.TransmitCompression = clientToServerCompression;
            }
            
            if (Role == SessionRole.Server)
                _exchangeContext.ClientKexInitPayload = message.SerializePacket();
            else
                _exchangeContext.ServerKexInitPayload = message.SerializePacket();

            DoExchange();
        }

        protected void HandleMessage(NewKeysMessage message)
        {
            _hasBlockedMessagesWaitHandle.Reset();

            lock (_locker)
            {
                _inboundFlow = 0;
                _outboundFlow = 0;
                _algorithms = _exchangeContext.NewAlgorithms;
                _exchangeContext = null;
            }

            ContinueSendBlockedMessages();
            _hasBlockedMessagesWaitHandle.Set();
        }

        protected void HandleMessage(UnimplementedMessage message)
        {
        }
        
        #endregion

        protected abstract void DoExchange();

        private string ChooseAlgorithm(string[] serverAlgorithms, string[] clientAlgorithms)
        {
            foreach (var client in clientAlgorithms)
                foreach (var server in serverAlgorithms)
                    if (client == server)
                        return client;

            throw new SshConnectionException("Failed to negotiate algorithm.", DisconnectReason.KeyExchangeFailed);
        }

        protected byte[] ComputeExchangeHash(KexAlgorithm kexAlg, byte[] hostKeyAndCerts, byte[] clientExchangeValue, byte[] serverExchangeValue, byte[] sharedSecret)
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

                worker.WriteBinary(_exchangeContext.ClientKexInitPayload);
                worker.WriteBinary(_exchangeContext.ServerKexInitPayload);
                worker.WriteBinary(hostKeyAndCerts);
                worker.WriteMpint(clientExchangeValue);
                worker.WriteMpint(serverExchangeValue);
                worker.WriteMpint(sharedSecret);

                return kexAlg.ComputeHash(worker.ToByteArray());
            }
        }

        protected byte[] ComputeEncryptionKey(KexAlgorithm kexAlg, byte[] exchangeHash, int blockSize, byte[] sharedSecret, char letter)
        {
            var keyBuffer = new byte[blockSize];
            var keyBufferIndex = 0;
            var currentHashLength = 0;
            byte[] currentHash = null;

            while (keyBufferIndex < blockSize)
            {
                using (var worker = new SshDataWorker())
                {
                    worker.WriteMpint(sharedSecret);
                    worker.Write(exchangeHash);

                    if (currentHash == null)
                    {
                        worker.Write((byte)letter);
                        worker.Write(SessionId);
                    }
                    else
                    {
                        worker.Write(currentHash);
                    }

                    currentHash = kexAlg.ComputeHash(worker.ToByteArray());
                }

                currentHashLength = Math.Min(currentHash.Length, blockSize - keyBufferIndex);
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
                worker.Write(payload);

                return alg.ComputeHash(worker.ToByteArray());
            }
        }

        protected class Algorithms
        {
            public KexAlgorithm KeyExchange;
            public PublicKeyAlgorithm ServerIdentification;
            public EncryptionAlgorithm ReceiveEncryption;
            public EncryptionAlgorithm TransmitEncryption;
            public HmacAlgorithm ReceiveHmac;
            public HmacAlgorithm TransmitHmac;
            public CompressionAlgorithm ReceiveCompression;
            public CompressionAlgorithm TransmitCompression;
        }

        protected class ExchangeContext
        {
            public string KeyExchange;
            public string PublicKey;
            public string ReceiveEncryption;
            public string TransmitEncryption;
            public string ReceiveHmac;
            public string TransmitHmac;
            public string ReceiveCompression;
            public string TransmitCompression;

            public byte[] ServerKexInitPayload;
            public byte[] ClientKexInitPayload;

            public Algorithms NewAlgorithms;
        }
    }
}
