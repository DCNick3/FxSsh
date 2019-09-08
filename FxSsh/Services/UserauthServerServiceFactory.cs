using System.Collections.Generic;
using System.Linq;
using FxSsh.Services.Userauth;
using FxSsh.Services.Userauth.Server;
using FxSsh.Transport;

namespace FxSsh.Services
{
    public class UserauthServerServiceFactory : ISshServerServiceFactory
    {
        private readonly IReadOnlyList<IServerMethodFactory> _methods;
        private readonly IServerAuthenticator _authenticator;

        public UserauthServerServiceFactory(IReadOnlyList<IServerMethodFactory> methods, IServerAuthenticator authenticator)
        {
            _methods = methods;
            _authenticator = authenticator;
        }
        
        public ISshService CreateService(ServerSession session, AuthInfo auth)
        {
            return new UserauthServerService(session, _methods.Select(_ => _.CreateMethod(session)), _authenticator);
        }

        public string GetServiceName()
        {
            return UserauthService.ServiceName;
        }
    }
}