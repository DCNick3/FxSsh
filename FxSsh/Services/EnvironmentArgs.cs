using System.Diagnostics.Contracts;
using FxSsh.Services.Userauth;

namespace FxSsh.Services
{
    public class EnvironmentArgs
    {
        public EnvironmentArgs(SessionChannel channel, string name, string value, AuthInfo authInfo)
        {
            Contract.Requires(channel != null);
            Contract.Requires(name != null);
            Contract.Requires(value != null);
            Contract.Requires(authInfo != null);

            Channel = channel;
            Name = name;
            Value = value;
            AttachedAuthInfo = authInfo;
        }

        public SessionChannel Channel { get; }
        public string Name { get; }
        public string Value { get; }
        public AuthInfo AttachedAuthInfo { get; }
    }
}