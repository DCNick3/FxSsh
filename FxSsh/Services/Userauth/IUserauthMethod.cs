using System;
using System.Collections.Generic;

namespace FxSsh.Services.Userauth
{
    public interface IUserauthMethod : IMessageHandler
    {
        string GetName();
        IReadOnlyDictionary<byte, Type> UsedMessageTypes();
        Type RequestType();
        bool IsUsable();
    }

    public interface IUserauthClientMethod : IUserauthMethod
    {
        void Configure(ClientSession session, string username, string serviceName);
        void InitiateAuth();
    }

    public interface IUserauthServerMethod : IUserauthMethod
    {
        void Configure(ServerSession session, Action<AuthInfo> succeedCallback, Action<AuthInfo> failedCallback);
    }
}