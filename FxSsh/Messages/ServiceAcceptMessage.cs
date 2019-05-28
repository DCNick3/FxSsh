using System.Text;

namespace FxSsh.Messages
{
    [Message("SSH_MSG_SERVICE_ACCEPT", MessageNumber)]
    public class ServiceAcceptMessage : Message
    {
        public const byte MessageNumber = 6;

        public ServiceAcceptMessage(string name)
        {
            ServiceName = name;
        }

        public string ServiceName { get; private set; }

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