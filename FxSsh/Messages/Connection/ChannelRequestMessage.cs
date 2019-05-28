using System.Text;

namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_CHANNEL_REQUEST", MessageNumber)]
    public class ChannelRequestMessage : ConnectionServiceMessage
    {
        public const byte MessageNumber = 98;

        public uint RecipientChannel { get; set; }
        public string RequestType { get; set; }
        public bool WantReply { get; set; }

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            RecipientChannel = reader.ReadUInt32();
            RequestType = reader.ReadString(Encoding.ASCII);
            WantReply = reader.ReadBoolean();
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(RecipientChannel);
            writer.Write(RequestType, Encoding.ASCII);
            writer.Write(WantReply);
        }
    }
}