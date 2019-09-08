using System.Collections.Generic;

namespace FxSsh.Services.Userauth.Server
{
    /// <summary>
    /// Decides what auth methods must client pass to get authenticated
    /// </summary>
    public interface IServerAuthenticator
    {
        bool CheckAuth(IEnumerable<ServerMethod> methods);
    }
}