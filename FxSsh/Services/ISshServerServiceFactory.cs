using FxSsh.Services.Userauth;

namespace FxSsh.Services
{
    public interface ISshServerServiceFactory
    {
        ISshService CreateService(ServerSession session, AuthInfo auth);
        string GetServiceName();
    }
}