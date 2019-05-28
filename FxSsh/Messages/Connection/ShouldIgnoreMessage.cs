namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_IGNORE", MessageNumber)]
    public class ShouldIgnoreMessage : ConnectionServiceMessage
    {
        public const byte MessageNumber = 2;

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
        }
    }
}