using FxSsh.Messages;
using FxSsh.Messages.Userauth;
using System;
using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class UserauthService : SshService, IDynamicInvoker
    {
        private string _currentAuthMethod;
        
        // This should be generalized to allow multistage auth too
        private readonly string[] _allowedMethods = {"publickey", "password"};
        public UserauthService(ServerSession session)
            : base(session)
        {
        }

        public event EventHandler<UserauthArgs> Userauth;

        public event EventHandler<string> Succeed;

        protected internal override void CloseService()
        {
        }

        internal void HandleMessageCore(UserauthServiceMessage message)
        {
            Contract.Requires(message != null);

            this.InvokeHandleMessage(message);
        }

        public Message CreateMethodSpecificMessage(byte number)
        {
            switch (_currentAuthMethod)
            {
                case "publickey":
                    if (number == PublicKeyOkMessage.MessageNumber)
                        return new PublicKeyOkMessage();
                    break;
                case "password":
                    if (number == PasswordChangeRequestMessage.MessageNumber)
                        return new PasswordChangeRequestMessage();
                    break;
            }
            
            return new UnknownMessage();
        }

        private void HandleMessage(RequestMessage message)
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

        private void HandleMessage(PasswordRequestMessage message)
        {
            var verified = false;

            var args = new UserauthArgs(_session, message.Username, message.Password);
            
            Userauth?.Invoke(this, args);
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

                var args = new UserauthArgs(base._session, message.Username, message.KeyAlgorithmName,
                    keyAlg.GetFingerprint(), message.PublicKey);
                Userauth?.Invoke(this, args);
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
                        worker.WriteBinary(_session.SessionId);
                        worker.Write(message.PayloadWithoutSignature);

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
