using System;
using System.Net.Sockets;
using FxSsh.Messages;
using FxSsh.Services.Userauth;
using FxSsh.Services.Userauth.Client;

namespace FxSsh.Transport
{
    public class ClientSession : Session
    {
        private readonly ClientAuthParameters _authParameters;

        public ClientSession(Socket socket, string programVersion, ClientAuthParameters authParameters) : base(socket,
            programVersion)
        {
            _authParameters = authParameters;
        }

        public override SessionRole Role => SessionRole.Client;

        protected override void DoExchange()
        {
            exchangeContext.NewAlgorithms = new Algorithms
            {
                KeyExchange = CryptoAlgorithms.KeyExchangeAlgorithms[exchangeContext.KeyExchange].Create()
            };

            var clientKeyExchange = exchangeContext.NewAlgorithms.KeyExchange.CreateKeyExchange();

            var message = new KeyExchangeDhInitMessage
            {
                E = clientKeyExchange
            };

            SendMessage(message);
        }

        #region Handle messages

        protected void HandleMessage(KeyExchangeDhReplyMessage message)
        {
            // be VERY attentive, when editing this. Algorithm names are strings, though no static checks for you
            var kexAlg = exchangeContext.NewAlgorithms.KeyExchange;
            var hostKeyAlg = CryptoAlgorithms.PublicKeyAlgorithms[exchangeContext.ServerIdentification]
                .CreateFromKeyAndCertificatesData(message.HostKey);
            var receiveCipher = CryptoAlgorithms.EncryptionAlgorithms[exchangeContext.ReceiveEncryption];
            var transmitCipher = CryptoAlgorithms.EncryptionAlgorithms[exchangeContext.TransmitEncryption];
            var receiveHmac = CryptoAlgorithms.HmacAlgorithms[exchangeContext.ReceiveHmac];
            var transmitHmac = CryptoAlgorithms.HmacAlgorithms[exchangeContext.TransmitHmac];
            var receiveCompression = CryptoAlgorithms.CompressionAlgorithms[exchangeContext.ReceiveCompression];
            var transmitCompression = CryptoAlgorithms.CompressionAlgorithms[exchangeContext.TransmitCompression];

            var clientExchangeValue = kexAlg.CreateKeyExchange();
            var serverExchangeValue = message.F;
            var sharedSecret = kexAlg.DecryptKeyExchange(serverExchangeValue);
            var hostKeyAndCerts = message.HostKey;
            var exchangeHash = ComputeExchangeHash(kexAlg, hostKeyAndCerts, clientExchangeValue, serverExchangeValue,
                sharedSecret);

            if (!hostKeyAlg.VerifySignature(exchangeHash, message.Signature))
                throw new SshConnectionException("Host key verification failed", DisconnectReason.HostKeyNotVerifiable);

            Console.WriteLine($"Host key is {hostKeyAlg.GetFingerprint()}");

            if (SessionId == null)
                SessionId = exchangeHash;

            var transmitCipherIv =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitCipher.BlockSize / 8, sharedSecret, 'A');
            var receiveCipherIv =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveCipher.BlockSize / 8, sharedSecret, 'B');
            var transmitCipherKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitCipher.KeySize / 8, sharedSecret, 'C');
            var receiveCipherKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveCipher.KeySize / 8, sharedSecret, 'D');
            var transmitHmacKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitHmac.KeySize / 8, sharedSecret, 'E');
            var receiveHmacKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveHmac.KeySize / 8, sharedSecret, 'F');

            exchangeContext.NewAlgorithms = new Algorithms
            {
                KeyExchange = kexAlg,
                ServerIdentification = hostKeyAlg,
                ReceiveEncryption = receiveCipher.CreateDecryption(receiveCipherKey, receiveCipherIv),
                TransmitEncryption = transmitCipher.CreateEncryption(transmitCipherKey, transmitCipherIv),
                ReceiveHmac = receiveHmac.Create(receiveHmacKey),
                TransmitHmac = transmitHmac.Create(transmitHmacKey),
                ReceiveCompression = receiveCompression.Create(),
                TransmitCompression = transmitCompression.Create()
            };

            SendMessage(new NewKeysMessage());

            //TODO: What should we do here? In some protocol extensions this may need to be changed
            SendMessage(new ServiceRequestMessage
            {
                ServiceName = UserauthService.ServiceName
            });
        }

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(ServiceAcceptMessage message)
        {
            if (message.ServiceName == UserauthService.ServiceName)
                RegisterService(new UserauthClientService(_authParameters, this));
            else
                throw new SshConnectionException("Unknown service accepted", DisconnectReason.ProtocolError);
        }

        #endregion
    }
}