using System;
using FxSsh.Algorithms;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Server
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