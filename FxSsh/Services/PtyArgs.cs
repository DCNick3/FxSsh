using FxSsh.Services.Userauth.Server;

namespace FxSsh.Services
{
    public class PtyArgs
    {
        public PtyArgs(SessionChannel channel, string terminal, uint heightPx, uint heightRows, uint widthPx,
            uint widthChars, string modes, AuthInfo authInfo)
        {
            Channel = channel;
            Terminal = terminal;
            HeightPx = heightPx;
            HeightRows = heightRows;
            WidthPx = widthPx;
            WidthChars = widthChars;
            Modes = modes;

            AttachedAuthInfo = authInfo;
        }

        // ReSharper disable UnusedAutoPropertyAccessor.Global
        public SessionChannel Channel { get; }
        public string Terminal { get; }
        public uint HeightPx { get; }
        public uint HeightRows { get; }
        public uint WidthPx { get; }
        public uint WidthChars { get; }
        public string Modes { get; }
        public AuthInfo AttachedAuthInfo { get; }
        // ReSharper restore UnusedAutoPropertyAccessor.Global
    }
}