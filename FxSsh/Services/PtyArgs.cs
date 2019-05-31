using System.Diagnostics.Contracts;
using FxSsh.Services.Userauth;

namespace FxSsh.Services
{
    public class PtyArgs
    {
        public PtyArgs(SessionChannel channel, string terminal, uint heightPx, uint heightRows, uint widthPx,
            uint widthChars, string modes, AuthInfo authInfo)
        {
            Contract.Requires(channel != null);
            Contract.Requires(terminal != null);
            Contract.Requires(modes != null);
            Contract.Requires(authInfo != null);

            Channel = channel;
            Terminal = terminal;
            HeightPx = heightPx;
            HeightRows = heightRows;
            WidthPx = widthPx;
            WidthChars = widthChars;
            Modes = modes;

            AttachedAuthInfo = authInfo;
        }

        public SessionChannel Channel { get; }
        public string Terminal { get; }
        public uint HeightPx { get; }
        public uint HeightRows { get; }
        public uint WidthPx { get; }
        public uint WidthChars { get; }
        public string Modes { get; }
        public AuthInfo AttachedAuthInfo { get; }
    }
}