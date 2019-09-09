using FxSsh.Services.Userauth.Server;

namespace FxSsh.Services.Connection
{
    public class CommandRequestedArgs
    {
        public CommandRequestedArgs(SessionChannel channel, string type, string command, AuthInfo authInfo)
        {
            Channel = channel;
            ShellType = type;
            CommandText = command;
            AttachedAuthInfo = authInfo;
        }

        public SessionChannel Channel { get; }
        public string ShellType { get; }
        public string CommandText { get; }
        // ReSharper disable once UnusedAutoPropertyAccessor.Global
        public AuthInfo AttachedAuthInfo { get; }
    }
}