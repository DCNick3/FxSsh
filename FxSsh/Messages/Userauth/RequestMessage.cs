using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages.Userauth
{
    /// <summary>
    /// Class for all userauth requests. Concrete requests are instantiated
    ///     in UserauthServerService's RequestMessage handler
    /// </summary>
    [Message("SSH_MSG_USERAUTH_REQUEST", MessageNumber)]
    public class RequestMessage : UserauthServiceMessage
    {
        public const byte MessageNumber = 50;

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