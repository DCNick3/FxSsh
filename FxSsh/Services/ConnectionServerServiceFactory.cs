using FxSsh.Services.Connection;
using FxSsh.Services.Userauth.Server;
using FxSsh.Transport;

namespace FxSsh.Services
{
    public class ConnectionServerServiceFactory : ISshServerServiceFactory
    {
        public ISshService CreateService(ServerSession session, AuthInfo auth)
        {
            return new ConnectionService(session, auth);
        }

        public string GetServiceName()
        {
            return ConnectionService.ServiceName;
        }
    }
}