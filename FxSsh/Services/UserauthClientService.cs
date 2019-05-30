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
        private readonly ClientSession _session;
        private readonly List<PublicKeyAlgorithm> _unusedKeys;
        private bool _hostbasedUsed = false;
        private bool _passwordUsed = false;
        private string _lastPassword;

        private IReadOnlyList<string> _authorizationMethodsThatCanContinue;

        public UserauthClientService(ClientAuthParameters authParameters, ClientSession session) : base(session)
        {
            _authParameters = authParameters;
            _session = session;
            _unusedKeys = _authParameters.UserKeys.ToList();

            _currentAuthMethod = "none";
            _session.SendMessage(new RequestMessage
            {
                MethodName = "none",
                Username = authParameters.Username,
                ServiceName = authParameters.ServiceName
            });
        }

        private void ContinueAuth()
        {
            if (_authorizationMethodsThatCanContinue.Contains("publickey") && _unusedKeys.Count > 0)
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

            if (_authorizationMethodsThatCanContinue.Contains("hostbased") && !_hostbasedUsed &&
                _authParameters.HostAuth != null)
            {
                _currentAuthMethod = "hostbased";
                _hostbasedUsed = true;

                var hostbased = _authParameters.HostAuth.Value;

                var request = new HostbasedRequestMessage
                {
                    Username = _authParameters.Username,
                    ServiceName = _authParameters.ServiceName,
                    ClientName = hostbased.hostname,
                    HostUsername = hostbased.username,
                    PublicKeyAlgorithm = hostbased.hostKey.Name,
                    KeyAndCertificatesData = hostbased.hostKey.ExportKeyAndCertificatesData(),
                };

                using (var worker = new SshDataWorker())
                {
                    worker.Write(_session.SessionId);
                    worker.WriteRawBytes(request.SerializePacket());

                    request.Signature = hostbased.hostKey.CreateSignatureData(worker.ToByteArray());
                }
                
                _session.SendMessage(request);
                return;
            }

            if (_authorizationMethodsThatCanContinue.Contains("password") && !_passwordUsed &&
                _authParameters.PasswordAuthHandler != null)
            {
                _currentAuthMethod = "password";
                
                if (!_authParameters.PasswordAuthHandler.IsRetryable())
                    _passwordUsed = true;

                _lastPassword = _authParameters.PasswordAuthHandler.GetPassword();
                
                _session.SendMessage(new PasswordRequestMessage
                {
                    Password = _lastPassword,
                    Username = _authParameters.Username,
                    ServiceName = _authParameters.ServiceName,
                    IsPasswordUpdate = false
                });
                
                return;
            }

            throw new SshConnectionException("No more auth methods available", DisconnectReason.NoMoreAuthMethodsAvailable);
        }
        
        protected void HandleMessage(FailureMessage message)
        {
            _authorizationMethodsThatCanContinue = message.AuthorizationMethodsThatCanContinue;

            if (_currentAuthMethod == "password")
            {
                // Well, this is not shred, but best I can do
                _lastPassword = null;
            }
            
            ContinueAuth();
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

            using (var worker = new SshDataWorker())
            {
                worker.Write(_session.SessionId);
                worker.WriteRawBytes(request.SerializePacket());

                request.Signature = key.CreateSignatureData(worker.ToByteArray());
            }

            _session.SendMessage(request);
        }

        protected void HandleMessage(PasswordChangeRequestMessage message)
        {
            var newPassword = _authParameters.PasswordAuthHandler.ChangePassword(message.Prompt, message.LanguageTag);

            if (newPassword == null)
            {
                _passwordUsed = true;
                ContinueAuth();
            }

            var oldPassword = _lastPassword ?? _authParameters.PasswordAuthHandler.GetPassword();
            
            _session.SendMessage(new PasswordRequestMessage
            {
                Username = _authParameters.Username,
                ServiceName = _authParameters.ServiceName,
                IsPasswordUpdate = true,
                Password = oldPassword,
                NewPassword = newPassword
            });
        }

        protected void HandleMessage(SuccessMessage message)
        {
            _lastPassword = null;
            
            if (_authParameters.ServiceName == "ssh-connection")
            {
                Console.WriteLine("Auth succeed. Further stuff is not implemented yet.");
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
        bool IsRetryable();
        string GetPassword();
        string ChangePassword(string prompt, string language);
    }
}