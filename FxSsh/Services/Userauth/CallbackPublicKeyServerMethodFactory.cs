using System;
using FxSsh.Algorithms;

namespace FxSsh.Services.Userauth
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