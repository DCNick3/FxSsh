using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages.Userauth
{
    public class PasswordChangeRequestMessage : UserauthServiceMessage
    {
        public const byte MessageNumber = 60;

        public override byte MessageType => MessageNumber;

        public string Prompt { get; set; }
        public string Language { get; set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            Prompt = reader.ReadString(Encoding.UTF8);
            Language = reader.ReadString(Encoding.ASCII);
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(Prompt, Encoding.UTF8);
            writer.Write(Language ?? "en", Encoding.ASCII);
        }
    }
}