using System;
using System.Collections.Generic;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services.Userauth
{
    public abstract class NoneMethod : IMethod
    {
        public const string MethodName = "none";
        
        public string GetName() => MethodName;
        public IReadOnlyDictionary<byte, Type> UsedMessageTypes() => new Dictionary<byte, Type>();
        public Type RequestType() => typeof(NoneRequest);
        public abstract bool IsUsable();
    }
}