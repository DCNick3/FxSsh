using System.Diagnostics.Contracts;
using FxSsh.Services.Userauth;

namespace FxSsh.Services
{
    public class CommandRequestedArgs
    {
        public CommandRequestedArgs(SessionChannel channel, string type, string command, AuthInfo authInfo)
        {
            Contract.Requires(channel != null);
            Contract.Requires(command != null);
            Contract.Requires(authInfo != null);

            Channel = channel;
            ShellType = type;
            CommandText = command;
            AttachedAuthInfo = authInfo;
        }

        public SessionChannel Channel { get; }
        public string ShellType { get; }
        public string CommandText { get; }
        public AuthInfo AttachedAuthInfo { get; }
    }
}