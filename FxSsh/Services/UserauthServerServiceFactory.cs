using System.Collections.Generic;
using System.Linq;
using FxSsh.Services.Userauth;

namespace FxSsh.Services
{
    public class UserauthServerServiceFactory : ISshServerServiceFactory
    {
        private readonly IReadOnlyList<IServerMethodFactory> _methods;

        public UserauthServerServiceFactory(IReadOnlyList<IServerMethodFactory> methods)
        {
            _methods = methods;
        }
        
        public ISshService CreateService(ServerSession session, AuthInfo auth)
        {
            return new UserauthServerService(session, _methods.Select(_ => _.CreateMethod(session)));
        }

        public string GetServiceName()
        {
            return UserauthService.ServiceName;
        }
    }
}