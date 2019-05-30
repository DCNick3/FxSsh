using System;
using System.Collections.Generic;
using System.Linq;
using FxSsh.Algorithms;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services
{
    public class UserauthClientService : UserauthService
    {
        private readonly ClientAuthParameters _authParameters;
        private readonly bool _hostbasedUsed = false;
        private readonly ClientSession _session;
        private readonly List<PublicKeyAlgorithm> _unusedKeys;

        public UserauthClientService(ClientAuthParameters authParameters, ClientSession session) : base(session)
        {
            _authParameters = authParameters;
            _session = session;
            _unusedKeys = _authParameters.UserKeys.ToList();

            _session.SendMessage(new RequestMessage
            {
                MethodName = "none",
                Username = authParameters.Username,
                ServiceName = authParameters.ServiceName
            });
        }

        protected void HandleMessage(FailureMessage message)
        {
            if (message.AuthorizationMethodsThatCanContinue.Contains("publickey") && _unusedKeys.Count > 0)
            {
                _currentAuthMethod = "publickey";
                var key = _unusedKeys.First();
                _unusedKeys.RemoveAt(0);

                _session.SendMessage(new PublicKeyRequestMessage
                {
                    Username = _authParameters.Username,
                    ServiceName = _authParameters.ServiceName,
                    KeyAlgorithmName = key.Name,
                    PublicKey = key.ExportKeyAndCertificatesData(),
                    HasSignature = false
                });
                return;
            }

            if (message.AuthorizationMethodsThatCanContinue.Contains("hostbased") && !_hostbasedUsed &&
                _authParameters.HostAuth != null)
                _currentAuthMethod = "hostbased";

            //return;

            if (message.AuthorizationMethodsThatCanContinue.Contains("password") &&
                _authParameters.PasswordAuthHandler != null)
                _currentAuthMethod = "password";

            //return;

            throw new SshConnectionException("No auth methods available", DisconnectReason.NoMoreAuthMethodsAvailable);
        }

        protected void HandleMessage(PublicKeyOkMessage message)
        {
            var publicKey = message.PublicKey;
            var algorithmName = message.KeyAlgorithmName;

            PublicKeyAlgorithm key = null;
            foreach (var userKey in _authParameters.UserKeys)
                if (userKey.Name == algorithmName && userKey.ExportKeyAndCertificatesData().SequenceEqual(publicKey))
                {
                    key = userKey;
                    break;
                }

            if (key == null)
                throw new SshConnectionException("Server accepted nonexistent key", DisconnectReason.ProtocolError);

            var request = new PublicKeyRequestMessage
            {
                Username = _authParameters.Username,
                ServiceName = _authParameters.ServiceName,
                KeyAlgorithmName = key.Name,
                PublicKey = key.ExportKeyAndCertificatesData(),
                HasSignature = true
            };

            var worker = new SshDataWorker();
            worker.WriteBinary(_session.SessionId);
            worker.Write(request.SerializePacket());

            request.Signature = key.CreateSignatureData(worker.ToByteArray());

            _session.SendMessage(request);
        }

        protected void HandleMessage(SuccessMessage message)
        {
            if (_authParameters.ServiceName == "ssh-connection")
            {
                // YAY!!
                // TODO: Register a ConnectionClientService
            }
            else
            {
                throw new SshConnectionException("Unknown service accepted", DisconnectReason.ProtocolError);
            }
        }

        protected void HandleMessage(BannerMessage message)
        {
            _authParameters.OnBanner?.Invoke(this, new OnBannerEventArgs
            {
                Message = message.Message,
                Language = message.Language
            });
        }
    }

    public class ClientAuthParameters
    {
        public string Username { get; set; }
        public string ServiceName { get; set; }
        public IReadOnlyList<PublicKeyAlgorithm> UserKeys { get; set; }
        public IPasswordAuthHandler PasswordAuthHandler { get; set; }

        public (string hostname, string username, PublicKeyAlgorithm hostKey)? HostAuth { get; set; }

        public EventHandler<OnBannerEventArgs> OnBanner { get; set; }
    }

    public class OnBannerEventArgs
    {
        public string Message { get; set; }
        public string Language { get; set; }
    }

    public interface IPasswordAuthHandler
    {
    }
}