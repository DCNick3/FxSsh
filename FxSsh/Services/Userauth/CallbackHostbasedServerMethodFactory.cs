using System;
using FxSsh.Algorithms;

namespace FxSsh.Services.Userauth
{
    public class CallbackHostbasedServerMethodFactory : IServerMethodFactory
    {
        private readonly Func<(ServerSession sesion, string username, string serviceName, string hostname, string
            hostUsername, PublicKeyAlgorithm key), bool> _callback;

        public CallbackHostbasedServerMethodFactory(
            Func<(ServerSession sesion, string username, string serviceName, string hostname, string hostUsername,
                PublicKeyAlgorithm key), bool> callback)
        {
            _callback = callback;
        }
        
        public ServerMethod CreateMethod(ServerSession session)
        {
            return new ServerMethod(session, new CallbackHostbasedServerMethod(_callback));
        }
    }
}