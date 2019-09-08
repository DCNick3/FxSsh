using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Server
{
    public interface IServerMethodFactory
    {
        ServerMethod CreateMethod(ServerSession session);
    }
}