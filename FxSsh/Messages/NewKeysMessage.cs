using FxSsh.Util;

namespace FxSsh.Messages
{
    [Message("SSH_MSG_NEWKEYS", MessageNumber)]
    public class NewKeysMessage : Message
    {
        public const byte MessageNumber = 21;

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
        }
    }
}