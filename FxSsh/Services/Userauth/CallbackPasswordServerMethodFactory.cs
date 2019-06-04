using System;

namespace FxSsh.Services.Userauth
{
    public class CallbackPasswordServerMethodFactory : IServerMethodFactory
    {
        private Func<(ServerSession session, string username,string serviceName, string password), bool> _callback;

        public CallbackPasswordServerMethodFactory(Func<(ServerSession session, string username, string serviceName, string password), bool> callback)
        {
            _callback = callback;
        }

        public ServerMethod CreateMethod(ServerSession session)
        {
            return new ServerMethod(session, new CallbackPasswordServerMethod(_callback));
        }
    }
}