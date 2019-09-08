using System;
using System.Collections.Generic;
using FxSsh.Util;

namespace FxSsh.Services.Userauth
{
    public interface IMethod : IMessageHandler
    {
        string GetName();
        IReadOnlyDictionary<byte, Type> UsedMessageTypes();
        Type RequestType();
        bool IsUsable();
    }
}