using FxSsh.Services.Userauth.Server;

namespace FxSsh.Services.Connection
{
    public class EnvironmentArgs
    {
        public EnvironmentArgs(SessionChannel channel, string name, string value, AuthInfo authInfo)
        {
            Channel = channel;
            Name = name;
            Value = value;
            AttachedAuthInfo = authInfo;
        }

        // ReSharper disable once UnusedAutoPropertyAccessor.Global
        public SessionChannel Channel { get; }
        public string Name { get; }
        public string Value { get; }
        // ReSharper disable once UnusedAutoPropertyAccessor.Global
        public AuthInfo AttachedAuthInfo { get; }
    }
}