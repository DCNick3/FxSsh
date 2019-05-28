namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_CHANNEL_WINDOW_ADJUST", MessageNumber)]
    public class ChannelWindowAdjustMessage : ConnectionServiceMessage
    {
        public const byte MessageNumber = 93;

        public uint RecipientChannel { get; set; }
        public uint BytesToAdd { get; set; }

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            RecipientChannel = reader.ReadUInt32();
            BytesToAdd = reader.ReadUInt32();
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(RecipientChannel);
            writer.Write(BytesToAdd);
        }
    }
}