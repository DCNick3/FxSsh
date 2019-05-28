using System.Text;
using FxSsh.Messages.Connection;

namespace FxSsh.Messages
{
    public class SubsystemRequestMessage : ChannelRequestMessage
    {
        public string Name { get; private set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            Name = reader.ReadString(Encoding.ASCII);
        }
    }
}