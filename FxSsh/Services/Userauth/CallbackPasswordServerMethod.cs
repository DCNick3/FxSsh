using System;

namespace FxSsh.Services.Userauth
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