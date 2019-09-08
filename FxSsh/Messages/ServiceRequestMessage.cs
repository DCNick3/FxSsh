using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages
{
    [Message("SSH_MSG_SERVICE_REQUEST", MessageNumber)]
    public class ServiceRequestMessage : Message
    {
        public const byte MessageNumber = 5;

        public string ServiceName { get; set; }

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            ServiceName = reader.ReadString(Encoding.ASCII);
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(ServiceName, Encoding.ASCII);
        }
    }
}