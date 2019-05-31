using System.Collections.Generic;
using FxSsh.Services.Userauth;

namespace FxSsh.Services
{
    public class UserauthSshServerServiceFactory : ISshServerServiceFactory
    {
        private IReadOnlyList<IUserauthServerMethod> _methods;

        public UserauthSshServerServiceFactory(IReadOnlyList<IUserauthServerMethod> methods)
        {
            _methods = methods;
        }
        
        public ISshService CreateService(ServerSession session, AuthInfo auth)
        {
            return new UserauthServerService(session, _methods);
        }

        public string GetServiceName()
        {
            return UserauthService.ServiceName;
        }
    }
}