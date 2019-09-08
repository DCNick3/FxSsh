using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Client
{
    public interface IClientMethod : IMethod
    {
        void Configure(ClientSession session, string username, string serviceName);
        void InitiateAuth();
    }
}