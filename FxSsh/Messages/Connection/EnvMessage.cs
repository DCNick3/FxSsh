using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages.Connection
{
    public class EnvMessage : ChannelRequestMessage
    {
        public string Name { get; private set; }
        public string Value { get; private set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            Name = reader.ReadString(Encoding.ASCII);
            Value = reader.ReadString(Encoding.ASCII);
        }
    }
}