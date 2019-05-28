using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class CommandRequestedArgs
    {
        public CommandRequestedArgs(SessionChannel channel, string type, string command, UserauthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(command != null);
            Contract.Requires(userauthArgs != null);

            Channel = channel;
            ShellType = type;
            CommandText = command;
            AttachedUserauthArgs = userauthArgs;
        }

        public SessionChannel Channel { get; }
        public string ShellType { get; }
        public string CommandText { get; }
        public UserauthArgs AttachedUserauthArgs { get; }
    }
}