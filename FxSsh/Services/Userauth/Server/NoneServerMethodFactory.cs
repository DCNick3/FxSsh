using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Server
{
    public class NoneServerMethodFactory : IServerMethodFactory
    {   
        public ServerMethod CreateMethod(ServerSession session)
        {
            return new ServerMethod(session, new NoneServerMethod());
        }
    }
}