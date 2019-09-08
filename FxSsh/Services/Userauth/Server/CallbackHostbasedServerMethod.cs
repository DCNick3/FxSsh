using System;
using FxSsh.Algorithms;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Server
{
    public sealed class CallbackHostbasedServerMethod : HostbasedServerMethod
    {
        private readonly Func<(ServerSession sesion, string username, string serviceName, string hostname, string hostUsername,
            PublicKeyAlgorithm key), bool> _callback;

        public CallbackHostbasedServerMethod(
            Func<(ServerSession sesion, string username, string serviceName, string hostname, string hostUsername,
                PublicKeyAlgorithm key), bool> callback)
        {
            _callback = callback;
        }

        protected override bool CheckHost(string username, string serviceName, string hostname, string hostUsername, PublicKeyAlgorithm key)
        {
            return _callback((Session, username, serviceName, hostname, hostUsername, key));
        }
    }
}