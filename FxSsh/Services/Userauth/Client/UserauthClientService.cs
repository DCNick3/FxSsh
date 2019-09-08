using System;
using System.Collections.Generic;
using System.Linq;
using FxSsh.Messages.Userauth;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Client
{
    public sealed class UserauthClientService : UserauthService
    {
        private readonly ClientAuthParameters _authParameters;

        private IReadOnlyList<IClientMethod> _authorizationMethodsThatCanContinue;

        public UserauthClientService(ClientAuthParameters authParameters, ClientSession session) : base(session)
        {
            _authParameters = authParameters;

            foreach (var method in _authParameters.Methods)
                method.Configure(session, _authParameters.Username, _authParameters.ServiceName);

            var noneMethod = new NoneClientMethod();
            noneMethod.Configure(session, _authParameters.Username, _authParameters.ServiceName);
            _authorizationMethodsThatCanContinue = new[] {noneMethod};
            ContinueAuth();
        }

        protected override void UseUserauthMethod(IMethod method)
        {
            var clientMethod = method as IClientMethod;
            if (method != null && clientMethod == null)
                throw new ArgumentOutOfRangeException(nameof(method));
            base.UseUserauthMethod(method);
            
            clientMethod?.InitiateAuth();
        }

        private void ContinueAuth()
        {
            /*
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
            */

            if (_authorizationMethodsThatCanContinue.Count > 0)
            {
                var method = _authorizationMethodsThatCanContinue.First();
                UseUserauthMethod(method);
            }
            else
                throw new SshConnectionException("No more auth methods available", DisconnectReason.NoMoreAuthMethodsAvailable);
        }

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(FailureMessage message)
        {
            var allowedNames = new HashSet<string>(message.AuthorizationMethodsThatCanContinue);
            _authorizationMethodsThatCanContinue = _authParameters.Methods
                .Where(_ => allowedNames.Contains(_.GetName()) && _.IsUsable()).ToArray();

            ContinueAuth();
        }
        
        // ReSharper disable once UnusedMember.Local
        // ReSharper disable once UnusedParameter.Local
        private void HandleMessage(SuccessMessage message)
        {
            if (_authParameters.ServiceName == "ssh-connection")
            {
                Console.WriteLine("Auth succeed. Further stuff is not implemented yet.");
                // YAY!!
                // TODO: Register a ConnectionClientService... Should poke the factory probably
            }
            else
                throw new SshConnectionException("Unknown service accepted", DisconnectReason.ProtocolError);
        }

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(BannerMessage message)
        {
            _authParameters.OnBanner?.Invoke(this, new OnBannerEventArgs
            {
                Message = message.Message,
                Language = message.Language
            });
        }
    }
}