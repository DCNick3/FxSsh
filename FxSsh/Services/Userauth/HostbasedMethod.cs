using System;
using System.Collections.Generic;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services.Userauth
{
    public abstract class HostbasedMethod : IMethod
    {
        public const string MethodName = "hostbased";
        
        public string GetName() => MethodName;
        public IReadOnlyDictionary<byte, Type> UsedMessageTypes() => new Dictionary<byte, Type>();
        public Type RequestType() => typeof(HostbasedRequestMessage);
        public abstract bool IsUsable();
    }
}