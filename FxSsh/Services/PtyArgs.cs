using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class PtyArgs
    {
        public PtyArgs(SessionChannel channel, string terminal, uint heightPx, uint heightRows, uint widthPx,
            uint widthChars, string modes, UserauthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(terminal != null);
            Contract.Requires(modes != null);
            Contract.Requires(userauthArgs != null);

            Channel = channel;
            Terminal = terminal;
            HeightPx = heightPx;
            HeightRows = heightRows;
            WidthPx = widthPx;
            WidthChars = widthChars;
            Modes = modes;

            AttachedUserauthArgs = userauthArgs;
        }

        public SessionChannel Channel { get; }
        public string Terminal { get; }
        public uint HeightPx { get; }
        public uint HeightRows { get; }
        public uint WidthPx { get; }
        public uint WidthChars { get; }
        public string Modes { get; }
        public UserauthArgs AttachedUserauthArgs { get; }
    }
}