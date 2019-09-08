using FxSsh.Util;

namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_CHANNEL_SUCCESS", MessageNumber)]
    public class ChannelSuccessMessage : ConnectionServiceMessage
    {
        public const byte MessageNumber = 99;

        public uint RecipientChannel { get; set; }

        public override byte MessageType => MessageNumber;

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(RecipientChannel);
        }
    }
}