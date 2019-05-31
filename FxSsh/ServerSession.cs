using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Net.Sockets;
using FxSsh.Messages;
using FxSsh.Services;
using FxSsh.Services.Userauth;

namespace FxSsh
{
    public class ServerSession : Session
    {
        private readonly IReadOnlyDictionary<string, byte[]> _hostKey;
        private readonly IReadOnlyDictionary<string, ISshServerServiceFactory> _serviceFactories;

        public ServerSession(Socket socket, IReadOnlyDictionary<string, byte[]> hostKey,
            IReadOnlyDictionary<string, ISshServerServiceFactory> serviceFactories, string programVersion) : base(
            socket, programVersion)
        {
            _hostKey = hostKey;
            _serviceFactories = serviceFactories;
        }

        public override SessionRole Role => SessionRole.Server;

        protected override KeyExchangeInitMessage LoadKexInitMessage()
        {
            var m = base.LoadKexInitMessage();
            m.ServerHostKeyAlgorithms = m.ServerHostKeyAlgorithms.Where(_ => _hostKey.ContainsKey(_)).ToArray();
            return m;
        }

        internal ISshService RegisterService(string serviceName, AuthInfo auth = null)
        {
            Contract.Requires(serviceName != null);

            if (_serviceFactories.TryGetValue(serviceName, out var factory))
            {
                var service = factory.CreateService(this, auth);

                if (service != null)
                    RegisterService(service);

                return service;
            }

            return null;
        }

        protected override void DoExchange()
        {
            // Nothing to do here, as in diffie-hellman key exchange protocol client initiates exchange  
        }

        #region Handle messages

        protected void HandleMessage(KeyExchangeDhInitMessage message)
        {
            var kexAlg = _keyExchangeAlgorithms[_exchangeContext.KeyExchange]();
            var hostKeyAlg = _publicKeyAlgorithms[_exchangeContext.PublicKey]
                .FromCspBlob(_hostKey[_exchangeContext.PublicKey]);
            var receiveCipher = _encryptionAlgorithms[_exchangeContext.ReceiveEncryption]();
            var transmitCipher = _encryptionAlgorithms[_exchangeContext.TransmitEncryption]();
            var transmitHmac = _hmacAlgorithms[_exchangeContext.TransmitHmac]();
            var receiveHmac = _hmacAlgorithms[_exchangeContext.ReceiveHmac]();

            var clientExchangeValue = message.E;
            var serverExchangeValue = kexAlg.CreateKeyExchange();
            var sharedSecret = kexAlg.DecryptKeyExchange(clientExchangeValue);
            var hostKeyAndCerts = hostKeyAlg.ExportKeyAndCertificatesData();
            var exchangeHash = ComputeExchangeHash(kexAlg, hostKeyAndCerts, clientExchangeValue, serverExchangeValue,
                sharedSecret);

            if (SessionId == null)
                SessionId = exchangeHash;

            // Maybe use client-to-server and server-to-client notation here too?
            var receiveCipherIV =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveCipher.BlockSize >> 3, sharedSecret, 'A');
            var transmitCipherIV =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitCipher.BlockSize >> 3, sharedSecret, 'B');
            var receiveCipherKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveCipher.KeySize >> 3, sharedSecret, 'C');
            var transmitCipherKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitCipher.KeySize >> 3, sharedSecret, 'D');
            var receiveHmacKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveHmac.KeySize >> 3, sharedSecret, 'E');
            var transmitHmacKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitHmac.KeySize >> 3, sharedSecret, 'F');

            _exchangeContext.NewAlgorithms = new Algorithms
            {
                KeyExchange = kexAlg,
                ServerIdentification = hostKeyAlg,
                ReceiveEncryption = receiveCipher.Cipher(receiveCipherKey, receiveCipherIV, false),
                TransmitEncryption = transmitCipher.Cipher(transmitCipherKey, transmitCipherIV, true),
                ReceiveHmac = receiveHmac.Hmac(receiveHmacKey),
                TransmitHmac = transmitHmac.Hmac(transmitHmacKey),
                ReceiveCompression = _compressionAlgorithms[_exchangeContext.ReceiveCompression](),
                TransmitCompression = _compressionAlgorithms[_exchangeContext.TransmitCompression]()
            };

            var reply = new KeyExchangeDhReplyMessage
            {
                HostKey = hostKeyAndCerts,
                F = serverExchangeValue,
                Signature = hostKeyAlg.CreateSignatureData(exchangeHash)
            };

            SendMessage(reply);
            SendMessage(new NewKeysMessage());
        }

        protected void HandleMessage(ServiceRequestMessage message)
        {
            var service = RegisterService(message.ServiceName);
            if (service != null)
            {
                SendMessage(new ServiceAcceptMessage(message.ServiceName));
                return;
            }

            throw new SshConnectionException(string.Format("Service \"{0}\" not available.", message.ServiceName),
                DisconnectReason.ServiceNotAvailable);
        }

        protected void HandleMessage(ConnectionServiceMessage message)
        {
            var service = GetService<ConnectionService>();
            service?.HandleMessageCore(message);
        }

        #endregion
    }
}