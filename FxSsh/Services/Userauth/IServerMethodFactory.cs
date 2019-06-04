namespace FxSsh.Services.Userauth
{
    public interface IServerMethodFactory
    {
        ServerMethod CreateMethod(ServerSession session);
    }
}