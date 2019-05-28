using System.Text;

namespace FxSsh.Messages.Userauth
{
    public class PasswordChangeRequestMessage : Message
    {
        public const byte MessageNumber = 60;

        public override byte MessageType => MessageNumber;

        public string Prompt { get; set; }
        public string LanguageTag { get; set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            Prompt = reader.ReadString(Encoding.UTF8);
            LanguageTag = reader.ReadString(Encoding.ASCII);
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(Prompt, Encoding.UTF8);
            writer.Write(LanguageTag, Encoding.ASCII);
        }
    }
}