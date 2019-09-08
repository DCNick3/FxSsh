using System;
using System.Collections.Generic;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services.Userauth
{
    public abstract class PasswordMethod : IMethod
    {
        public const string MethodName = "password";
        public string GetName() => MethodName;
        public IReadOnlyDictionary<byte, Type> UsedMessageTypes() =>
            new Dictionary<byte, Type>
            {
                {PasswordChangeRequestMessage.MessageNumber, typeof(PasswordChangeRequestMessage)}
            };

        public Type RequestType() => typeof(PasswordRequestMessage);
        public abstract bool IsUsable();
    }
}