using System;
using FxSsh.Messages.Userauth;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Server
{
    public abstract class PasswordServerMethod : PasswordMethod, IServerMethod
    {
        protected ServerSession Session;
        private Action<AuthInfo> _succeed;
        private Action<(AuthInfo auth, bool partial)> _failed;

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

        protected abstract bool CheckPassword(string username, string serviceName, string password);
        
        protected void HandleMessage(PasswordRequestMessage message)
        {
            var auth = new AuthInfo
            {
                Username = message.Username,
                Service = message.ServiceName
            };

            if (CheckPassword(message.Username, message.ServiceName, message.Password))
                _succeed(auth);
            else
                _failed((auth, false));
        }
    }
}