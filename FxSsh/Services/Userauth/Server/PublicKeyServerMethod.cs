using System;
using FxSsh.Algorithms;
using FxSsh.Messages.Userauth;
using FxSsh.Transport;
using FxSsh.Util;

namespace FxSsh.Services.Userauth.Server
{
    public abstract class PublicKeyServerMethod : PublicKeyMethod, IServerMethod
    {
        private Action<AuthInfo> _succeed;
        private Action<(AuthInfo auth, bool partial)> _failed;
        protected ServerSession Session;

        public override bool IsUsable()
        {
            return true;
        }

        public void Configure(ServerSession session, Action<AuthInfo> succeedCallback, Action<(AuthInfo auth, bool partial)> failedCallback)
        {
            Session = session;
            _succeed = succeedCallback;
            _failed = failedCallback;
        }

        protected abstract bool CheckKey(string username, string serviceName, PublicKeyAlgorithm key);
            
        protected void HandleMessage(PublicKeyRequestMessage message)
        {
            var args = new AuthInfo
            {
                Service = message.ServiceName,
                Username = message.Username
            };
            
            var key = CryptoAlgorithms.PublicKeyAlgorithms[message.KeyAlgorithmName]
                .CreateFromKeyAndCertificatesData(message.PublicKey);
            var valid = CheckKey(message.Username, message.ServiceName, key);

            if (!valid)
            {
                _failed((args, false));
                return;
            }

            if (!message.HasSignature)
            {
                Session.SendMessage(new PublicKeyOkMessage
                {
                    KeyAlgorithmName = message.KeyAlgorithmName,
                    PublicKey = message.PublicKey
                });
            }
            else
            {
                using (var worker = new SshDataWorker())
                {
                    worker.Write(Session.SessionId);
                    worker.WriteRawBytes(message.PayloadWithoutSignature);

                    valid = key.VerifySignature(worker.ToByteArray(), message.Signature);
                }

                if (valid)
                    _succeed(args);
                else
                    _failed((args, false));
            }
        }
    }
}