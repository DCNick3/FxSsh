using System;
using System.Net.Sockets;
using FxSsh.Messages;
using FxSsh.Services;

namespace FxSsh
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
            _exchangeContext.NewAlgorithms = new Algorithms
            {
                KeyExchange = _keyExchangeAlgorithms[_exchangeContext.KeyExchange]()
            };

            var clientKeyExchange = _exchangeContext.NewAlgorithms.KeyExchange.CreateKeyExchange();

            var message = new KeyExchangeDhInitMessage
            {
                E = clientKeyExchange
            };

            SendMessage(message);
        }

        #region Handle messages

        protected void HandleMessage(KeyExchangeDhReplyMessage message)
        {
            var kexAlg = _exchangeContext.NewAlgorithms.KeyExchange;
            var hostKeyAlg = _publicKeyAlgorithms[_exchangeContext.PublicKey]
                .FromKeyAndCertificatesData(message.HostKey);
            var receiveCipher = _encryptionAlgorithms[_exchangeContext.ReceiveEncryption]();
            var transmitCipher = _encryptionAlgorithms[_exchangeContext.TransmitEncryption]();
            var transmitHmac = _hmacAlgorithms[_exchangeContext.TransmitHmac]();
            var receiveHmac = _hmacAlgorithms[_exchangeContext.ReceiveHmac]();

            var clientExchangeValue = kexAlg.CreateKeyExchange();
            var serverExchangeValue = message.F;
            var sharedSecret = kexAlg.DecryptKeyExchange(serverExchangeValue);
            var hostKeyAndCerts = message.HostKey;
            var exchangeHash = ComputeExchangeHash(kexAlg, hostKeyAndCerts, clientExchangeValue, serverExchangeValue,
                sharedSecret);

            if (!hostKeyAlg.VerifyData(exchangeHash, hostKeyAlg.GetSignature(message.Signature)))
                throw new SshConnectionException("Host key verification failed", DisconnectReason.HostKeyNotVerifiable);

            Console.WriteLine($"Host key is {hostKeyAlg.GetFingerprint("sha256")}");

            if (SessionId == null)
                SessionId = exchangeHash;

            // Maybe use client-to-server and server-to-client notation here too?
            var transmitCipherIV =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitCipher.BlockSize >> 3, sharedSecret, 'A');
            var receiveCipherIV =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveCipher.BlockSize >> 3, sharedSecret, 'B');
            var transmitCipherKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitCipher.KeySize >> 3, sharedSecret, 'C');
            var receiveCipherKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveCipher.KeySize >> 3, sharedSecret, 'D');
            var transmitHmacKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, transmitHmac.KeySize >> 3, sharedSecret, 'E');
            var receiveHmacKey =
                ComputeEncryptionKey(kexAlg, exchangeHash, receiveHmac.KeySize >> 3, sharedSecret, 'F');

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

            SendMessage(new NewKeysMessage());

            SendMessage(new ServiceRequestMessage
            {
                ServiceName = "ssh-userauth"
            });
        }

        private void HandleMessage(ServiceAcceptMessage message)
        {
            if (message.ServiceName == "ssh-userauth")
                RegisterService(new UserauthClientService(_authParameters, this));
            else
                throw new SshConnectionException("Unknown service accepted", DisconnectReason.ProtocolError);
        }

        #endregion
    }
}