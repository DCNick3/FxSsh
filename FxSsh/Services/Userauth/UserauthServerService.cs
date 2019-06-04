using System;
using System.Collections.Generic;
using System.Linq;
using FxSsh.Messages;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services.Userauth
{
    public sealed class UserauthServerService : UserauthService
    {
        // This should be generalized to allow multistage auth too
        private readonly Dictionary<string, ServerMethod> _allowedMethods;
        private readonly ServerSession _session;

        private IReadOnlyList<string> AuthorizationMethodsThatCanContinue => _allowedMethods.Values
            .Where(_ => _.Usable)
            .Select(_ => _.Name)
            .Where(_ => _ != NoneMethod.MethodName) // this is prohibited by RFC
            .ToArray();

        public UserauthServerService(ServerSession session, IEnumerable<ServerMethod> allowedMethods) : base(session)
        {
            _session = session;
            _allowedMethods = allowedMethods.ToDictionary(_ => _.Name);
            
            foreach (var method in _allowedMethods.Values)
            {
                method.OnFailure += AuthMethodFailed;
                method.OnSuccess += AuthMethodSucceed;
            }
        }
        
        public event EventHandler<AuthInfo> Succeed;
        public event EventHandler<AuthInfo> Failed;

        private void HandleMessage(RequestMessage message)
        {
            if (_allowedMethods.TryGetValue(message.MethodName, out var method) && method.Usable)
            {
                var requestMessage = Message.LoadFrom(message, method.RequestType);
                method.InvokeHandleMessage(requestMessage);
            }
            else
            {
                _session.SendMessage(new FailureMessage
                {
                    PartialSuccess = false,
                    AuthorizationMethodsThatCanContinue = AuthorizationMethodsThatCanContinue
                });
            }
        }

        // TODO: add support for multi-stage auth
        private void AuthMethodSucceed(object sender, AuthInfo args)
        {
            Succeed?.Invoke(this, args);
            _session.SendMessage(new SuccessMessage());
            _session.RegisterService(args.Service, args);
        }

        private void AuthMethodFailed(object sender, (AuthInfo auth, bool partial) args)
        {
            var (auth, partial) = args;
            
            Failed?.Invoke(this, auth);
            _session.SendMessage(new FailureMessage
            {
                PartialSuccess = partial,
                AuthorizationMethodsThatCanContinue = AuthorizationMethodsThatCanContinue
            });
        }

        /*
        private void HandleMessage(PasswordRequestMessage message)
        {
            var verified = false;

            var args = new UserauthArgs(_session, message.Username, message.Password);

            CheckAuthData?.Invoke(this, args);
            verified = args.Result;

            if (verified)
            {
                _session.RegisterService(message.ServiceName, args);

                Succeed?.Invoke(this, message.ServiceName);

                _session.SendMessage(new SuccessMessage());
            }
            else
            {
                _session.SendMessage(new FailureMessage
                {
                    AuthorizationMethodsThatCanContinue = _allowedMethods,
                    PartialSuccess = false
                });
            }
        }

        private void HandleMessage(PublicKeyRequestMessage message)
        {
            if (Session._publicKeyAlgorithms.ContainsKey(message.KeyAlgorithmName))
            {
                var verified = false;

                var keyAlg = Session._publicKeyAlgorithms[message.KeyAlgorithmName]
                    .FromKeyAndCertificatesData(message.PublicKey);

                var args = new UserauthArgs(_session, message.Username, message.KeyAlgorithmName,
                    keyAlg.GetFingerprint(), message.PublicKey);
                CheckAuthData?.Invoke(this, args);
                verified = args.Result;

                if (verified)
                {
                    if (!message.HasSignature)
                    {
                        _session.SendMessage(new PublicKeyOkMessage
                            {KeyAlgorithmName = message.KeyAlgorithmName, PublicKey = message.PublicKey});
                        return;
                    }

                    var sig = keyAlg.GetSignature(message.Signature);

                    using (var worker = new SshDataWorker())
                    {
                        worker.Write(_session.SessionId);
                        worker.WriteRawBytes(message.PayloadWithoutSignature);

                        verified = keyAlg.VerifyData(worker.ToByteArray(), sig);
                    }

                    if (verified)
                    {
                        _session.RegisterService(message.ServiceName, args);
                        Succeed?.Invoke(this, message.ServiceName);
                        _session.SendMessage(new SuccessMessage());
                    }
                }
            }

            _session.SendMessage(new FailureMessage
            {
                AuthorizationMethodsThatCanContinue = _allowedMethods,
                PartialSuccess = false
            });
        }
        */
    }
}