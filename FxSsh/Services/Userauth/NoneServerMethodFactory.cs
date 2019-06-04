namespace FxSsh.Services.Userauth
{
    public class NoneServerMethodFactory : IServerMethodFactory
    {   
        public ServerMethod CreateMethod(ServerSession session)
        {
            return new ServerMethod(session, new NoneServerMethod());
        }
    }
}