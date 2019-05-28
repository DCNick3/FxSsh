using System.Text;

namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_CHANNEL_OPEN", MessageNumber)]
    public class ChannelOpenMessage : ConnectionServiceMessage
    {
        public const byte MessageNumber = 90;

        public string ChannelType { get; private set; }
        public uint SenderChannel { get; private set; }
        public uint InitialWindowSize { get; private set; }
        public uint MaximumPacketSize { get; private set; }

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            ChannelType = reader.ReadString(Encoding.ASCII);
            SenderChannel = reader.ReadUInt32();
            InitialWindowSize = reader.ReadUInt32();
            MaximumPacketSize = reader.ReadUInt32();
        }
    }
}