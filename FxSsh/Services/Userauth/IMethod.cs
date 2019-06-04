using System;
using System.Collections.Generic;

namespace FxSsh.Services.Userauth
{
    public interface IMethod : IMessageHandler
    {
        string GetName();
        IReadOnlyDictionary<byte, Type> UsedMessageTypes();
        Type RequestType();
        bool IsUsable();
    }

    public interface IClientMethod : IMethod
    {
        void Configure(ClientSession session, string username, string serviceName);
        void InitiateAuth();
    }

    public interface IServerMethod : IMethod
    {
        void Configure(ServerSession session, Action<AuthInfo> succeedCallback, Action<(AuthInfo auth, bool partial)> failedCallback);
    }
}