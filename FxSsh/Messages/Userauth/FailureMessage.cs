using System.Collections.Generic;
using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages.Userauth
{
    [Message("SSH_MSG_USERAUTH_FAILURE", MessageNumber)]
    public class FailureMessage : UserauthServiceMessage
    {
        public const byte MessageNumber = 51;

        public override byte MessageType => MessageNumber;

        public IReadOnlyList<string> AuthorizationMethodsThatCanContinue { get; set; }
        public bool PartialSuccess { get; set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            AuthorizationMethodsThatCanContinue = reader.ReadString(Encoding.ASCII).Split(',');
            PartialSuccess = reader.ReadBoolean();
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(string.Join(",", AuthorizationMethodsThatCanContinue), Encoding.ASCII);
            writer.Write(PartialSuccess);
        }
    }
}