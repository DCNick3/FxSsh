using System;
using FxSsh.Algorithms;
using FxSsh.Messages.Userauth;
using FxSsh.Transport;
using FxSsh.Util;

namespace FxSsh.Services.Userauth.Server
{
    public abstract class HostbasedServerMethod : HostbasedMethod, IServerMethod
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

        protected abstract bool CheckHost(string username, string serviceName, string hostname, string hostUsername,
            PublicKeyAlgorithm key);

        protected void HandleMessage(HostbasedRequestMessage message)
        {
            var args = new AuthInfo
            {
                Service = message.ServiceName,
                Username = message.Username
            };
            
            var key = CryptoAlgorithms.PublicKeyAlgorithms[message.PublicKeyAlgorithm]
                .CreateFromKeyAndCertificatesData(message.KeyAndCertificatesData);

            var valid = CheckHost(message.Username, message.ServiceName, message.ClientName, message.HostUsername,
                key);

            if (!valid)
            {
                _failed((args, false));
                return;
            }

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