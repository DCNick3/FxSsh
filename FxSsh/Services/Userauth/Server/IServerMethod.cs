using System;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Server
{
    public interface IServerMethod : IMethod
    {
        void Configure(ServerSession session, Action<AuthInfo> succeedCallback, Action<(AuthInfo auth, bool partial)> failedCallback);
    }
}