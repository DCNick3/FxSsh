using System;
using FxSsh.Messages.Userauth;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Server
{
    public sealed class NoneServerMethod : NoneMethod, IServerMethod
    {
        private Action<AuthInfo> _succeed;
        private Action<(AuthInfo auth, bool partial)> _failed;

        public void Configure(ServerSession session, Action<AuthInfo> succeedCallback, Action<(AuthInfo auth, bool partial)> failedCallback)
        {
            _succeed = succeedCallback;
            _failed = failedCallback;
        }

        private void HandleMessage(NoneRequest message)
        {
            var args = new AuthInfo
            {
                Service = message.ServiceName,
                Username = message.Username
            };
            
            _succeed(args);
        }

        public override bool IsUsable() => false;
    }
}