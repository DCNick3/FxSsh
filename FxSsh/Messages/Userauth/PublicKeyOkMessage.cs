using System.Text;

namespace FxSsh.Messages.Userauth
{
    [Message("SSH_MSG_USERAUTH_PK_OK", MessageNumber)]
    public class PublicKeyOkMessage : UserauthServiceMessage
    {
        public const byte MessageNumber = 60;

        public string KeyAlgorithmName { get; set; }
        public byte[] PublicKey { get; set; }

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            KeyAlgorithmName = reader.ReadString(Encoding.ASCII);
            PublicKey = reader.ReadBinary();
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(KeyAlgorithmName, Encoding.ASCII);
            writer.Write(PublicKey);
        }
    }
}