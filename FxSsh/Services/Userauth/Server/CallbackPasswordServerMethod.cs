using System;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Server
{
    public sealed class CallbackPasswordServerMethod : PasswordServerMethod
    {
        private Func<(ServerSession session, string username, string serviceName, string password), bool> _callback;

        public CallbackPasswordServerMethod(Func<(ServerSession session, string username, string serviceName, string password), bool> callback)
        {
            _callback = callback;
        }

        protected override bool CheckPassword(string username, string serviceName, string password)
        {
            return _callback((Session, username, serviceName, password));
        }
    }
}