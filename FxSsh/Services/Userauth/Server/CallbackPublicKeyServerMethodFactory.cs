using System;
using FxSsh.Algorithms;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Server
{
    public sealed class CallbackPublicKeyServerMethodFactory : IServerMethodFactory
    {
        private readonly Func<(ServerSession session, string username, string serviceName, PublicKeyAlgorithm key), bool> _authCallback;

        public CallbackPublicKeyServerMethodFactory(
            Func<(ServerSession session, string username, string serviceName, PublicKeyAlgorithm key), bool> authCallback)
        {
            _authCallback = authCallback;
        }

        public ServerMethod CreateMethod(ServerSession session)
        {
            return new ServerMethod(session, new CallbackPublicKeyServerMethod(_authCallback));
        }
    }
}