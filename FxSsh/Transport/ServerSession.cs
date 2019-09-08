using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using FxSsh.Algorithms;
using FxSsh.Messages;
using FxSsh.Services;
using FxSsh.Services.Userauth.Server;

namespace FxSsh.Transport
{
    public class ServerSession : Session
    {
        private readonly IReadOnlyDictionary<string, PublicKeyAlgorithm> _hostKeys;
        private readonly IReadOnlyDictionary<string, ISshServerServiceFactory> _serviceFactories;

        public ServerSession(Socket socket, IReadOnlyDictionary<string, PublicKeyAlgorithm> hostKeys,
            IReadOnlyDictionary<string, ISshServerServiceFactory> serviceFactories, string programVersion) : base(
            socket, programVersion)
        {
            _hostKeys = hostKeys;
            _serviceFactories = serviceFactories;
        }

        public override SessionRole Role => SessionRole.Server;

        protected override KeyExchangeInitMessage LoadKexInitMessage()
        {
            var m = base.LoadKexInitMessage();
            m.ServerHostKeyAlgorithms = m.ServerHostKeyAlgorithms.Where(_ => _hostKeys.ContainsKey(_)).ToArray();
            return m;
        }

        internal ISshService RegisterService(string serviceName, AuthInfo auth = null)
        {
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
            // be VERY attentive, when editing this. Algorithm names are strings, though no static checks for you
            var kexAlg = CryptoAlgorithms.KeyExchangeAlgorithms[exchangeContext.KeyExchange].Create();
            var hostKeyAlg = _hostKeys[exchangeContext.ServerIdentification];
            var receiveEncryption= CryptoAlgorithms.EncryptionAlgorithms[exchangeContext.ReceiveEncryption];
            var transmitEncryption = CryptoAlgorithms.EncryptionAlgorithms[exchangeContext.TransmitEncryption];
            var receiveHmac = CryptoAlgorithms.HmacAlgorithms[exchangeContext.ReceiveHmac];
            var transmitHmac = CryptoAlgorithms.HmacAlgorithms[exchangeContext.TransmitHmac];
            var receiveCompression = CryptoAlgorithms.CompressionAlgorithms[exchangeContext.ReceiveCompression];
            var transmitCompression = CryptoAlgorithms.CompressionAlgorithms[exchangeContext.TransmitCompression];

            var clientExchangeValue = message.E;
            var serverExchangeValue = kexAlg.CreateKeyExchange();
            var sharedSecret = kexAlg.DecryptKeyExchange(clientExchangeValue);
            var hostKeyAndCerts = hostKeyAlg.ExportKeyAndCertificatesData();
            var exchangeHash = ComputeExchangeHash(kexAlg, hostKeyAndCerts, clientExchangeValue, serverExchangeValue,
                sharedSecret);

            if (SessionId == null)
                SessionId = exchangeHash;

            // Maybe use client-to-server and server-to-client notation here too?
            var receiveCipherIv =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveEncryption.BlockSize / 8, sharedSecret, 'A');
            var transmitCipherIv =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitEncryption.BlockSize / 8, sharedSecret, 'B');
            var receiveCipherKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveEncryption.KeySize / 8, sharedSecret, 'C');
            var transmitCipherKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitEncryption.KeySize / 8, sharedSecret, 'D');
            var receiveHmacKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveHmac.KeySize / 8, sharedSecret, 'E');
            var transmitHmacKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitHmac.KeySize / 8, sharedSecret, 'F');

            exchangeContext.NewAlgorithms = new Algorithms
            {
                KeyExchange = kexAlg,
                ServerIdentification = hostKeyAlg,
                ReceiveEncryption = receiveEncryption.CreateDecryption(receiveCipherKey, receiveCipherIv),
                TransmitEncryption = transmitEncryption.CreateEncryption(transmitCipherKey, transmitCipherIv),
                ReceiveHmac = receiveHmac.Create(receiveHmacKey),
                TransmitHmac = transmitHmac.Create(transmitHmacKey),
                ReceiveCompression = receiveCompression.Create(),
                TransmitCompression = transmitCompression.Create()
            };

            var reply = new KeyExchangeDhReplyMessage
            {
                HostKey = hostKeyAndCerts,
                F = serverExchangeValue,
                Signature = hostKeyAlg.CreateSignature(exchangeHash)
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

            throw new SshConnectionException($"Service \"{message.ServiceName}\" not available.",
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