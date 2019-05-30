using System;
using FxSsh.Messages;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services
{
    public class UserauthServerService : UserauthService
    {
        // This should be generalized to allow multistage auth too
        private readonly string[] _allowedMethods = {"publickey", "password"};
        private readonly ServerSession _session;


        public UserauthServerService(ServerSession session) : base(session)
        {
            _session = session;
        }

        public event EventHandler<UserauthArgs> CheckAuthData;
        public event EventHandler<string> Succeed;

        protected void HandleMessage(RequestMessage message)
        {
            _currentAuthMethod = message.MethodName;
            switch (message.MethodName)
            {
                case "publickey":
                    var keyMsg = Message.LoadFrom<PublicKeyRequestMessage>(message);
                    HandleMessage(keyMsg);
                    break;
                case "password":
                    var pswdMsg = Message.LoadFrom<PasswordRequestMessage>(message);
                    HandleMessage(pswdMsg);
                    break;
                case "hostbased":
                case "none":
                default:
                    _session.SendMessage(new FailureMessage
                    {
                        AuthorizationMethodsThatCanContinue = _allowedMethods,
                        PartialSuccess = false
                    });
                    break;
            }
        }

        protected void HandleMessage(PasswordRequestMessage message)
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

        protected void HandleMessage(PublicKeyRequestMessage message)
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
    }
}