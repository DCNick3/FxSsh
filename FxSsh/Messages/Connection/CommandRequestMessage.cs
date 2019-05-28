using System.Text;

namespace FxSsh.Messages.Connection
{
    public class CommandRequestMessage : ChannelRequestMessage
    {
        public string Command { get; private set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            Command = reader.ReadString(Encoding.ASCII);
        }
    }
}