using System.Text;

namespace FxSsh.Messages.Userauth
{
    public class BannerMessage : UserauthServiceMessage
    {
        public const byte MessageNumber = 53;

        public override byte MessageType => MessageNumber;

        public string Message { get; set; }
        public string Language { get; set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            Message = reader.ReadString(Encoding.UTF8);
            Language = reader.ReadString(Encoding.ASCII);
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(Message, Encoding.UTF8);
            writer.Write(Language ?? "en", Encoding.ASCII);
        }
    }
}