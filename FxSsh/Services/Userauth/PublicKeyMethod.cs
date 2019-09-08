using System;
using System.Collections.Generic;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services.Userauth
{
    public abstract class PublicKeyMethod : IMethod
    {
        public const string MethodName = "publickey";
        
        public string GetName() => MethodName;

        public IReadOnlyDictionary<byte, Type> UsedMessageTypes() =>
            new Dictionary<byte, Type>
            {
                { PublicKeyOkMessage.MessageNumber, typeof(PublicKeyOkMessage) }
            };
        public Type RequestType() => typeof(PublicKeyRequestMessage);
        public abstract bool IsUsable();
    }
}