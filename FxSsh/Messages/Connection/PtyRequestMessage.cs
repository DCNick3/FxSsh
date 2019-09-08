using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages.Connection
{
    public class PtyRequestMessage : ChannelRequestMessage
    {
        public uint heightPx;
        public uint heightRows;
        public string modes = "";
        public string Terminal = "";
        public uint widthChars;
        public uint widthPx;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            Terminal = reader.ReadString(Encoding.ASCII);
            widthChars = reader.ReadUInt32();
            heightRows = reader.ReadUInt32();
            widthPx = reader.ReadUInt32();
            heightPx = reader.ReadUInt32();
            modes = reader.ReadString(Encoding.ASCII);
        }
    }
}