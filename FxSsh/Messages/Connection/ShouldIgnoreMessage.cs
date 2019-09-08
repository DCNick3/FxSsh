using FxSsh.Util;

namespace FxSsh.Messages.Connection
{
    /*
     * Described in https://tools.ietf.org/html/rfc4251 at page 14.
     * Used to mitigate Rogaway attack. TODO: Look into implementing this
     */
    
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