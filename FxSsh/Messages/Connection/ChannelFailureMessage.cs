using FxSsh.Util;

namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_CHANNEL_FAILURE", MessageNumber)]
    public class ChannelFailureMessage : ConnectionServiceMessage
    {
        public const byte MessageNumber = 100;

        public uint RecipientChannel { get; set; }

        public override byte MessageType => MessageNumber;

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(RecipientChannel);
        }
    }
}