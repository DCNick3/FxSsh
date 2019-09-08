using System;
using FxSsh.Algorithms;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Server
{
    public sealed class CallbackPublicKeyServerMethod : PublicKeyServerMethod
    {
        private readonly Func<(ServerSession session, string username, string serviceName, PublicKeyAlgorithm key), bool> _callback;
        
        public CallbackPublicKeyServerMethod(Func<(ServerSession session, string username, string serviceName, PublicKeyAlgorithm key), bool> callback)
        {
            _callback = callback;
        }
        
        protected override bool CheckKey(string username, string serviceName, PublicKeyAlgorithm key)
        {
            return _callback((Session, username, serviceName, key));
        }
    }
}