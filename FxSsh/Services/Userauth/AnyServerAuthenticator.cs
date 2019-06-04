using System.Collections.Generic;
using System.Linq;

namespace FxSsh.Services.Userauth
{
    /// <summary>
    /// Authenticates if ANY of allowed methods are succeed
    /// </summary>
    public class AnyServerAuthenticator : IServerAuthenticator
    {
        public bool CheckAuth(IEnumerable<ServerMethod> methods)
        {
            return methods.Select(_ => _.Succeed).Any();
        }
    }
}