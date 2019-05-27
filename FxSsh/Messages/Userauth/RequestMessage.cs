using System.Text;

namespace FxSsh.Messages.Userauth
{
    [Message("SSH_MSG_USERAUTH_REQUEST", MessageNumber)]
    public class RequestMessage : UserauthServiceMessage
    {
        private const byte MessageNumber = 50;

        public string Username { get; set; }
        public string ServiceName { get; set; }
        public string MethodName { get; set; }

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            Username = reader.ReadString(Encoding.UTF8);
            ServiceName = reader.ReadString(Encoding.ASCII);
            MethodName = reader.ReadString(Encoding.ASCII);
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(Username, Encoding.UTF8);
            writer.Write(ServiceName, Encoding.ASCII);
            writer.Write(MethodName, Encoding.ASCII);
        }
    }
}
