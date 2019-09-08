using FxSsh.Services.Userauth.Server;
using FxSsh.Transport;

namespace FxSsh.Services
{
    public interface ISshServerServiceFactory
    {
        ISshService CreateService(ServerSession session, AuthInfo auth);
        string GetServiceName();
    }
}