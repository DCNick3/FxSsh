
namespace FxSsh.Messages.Connection
{
    public class ExitStatusMessage : ChannelRequestMessage
    {
        public uint ExitStatus { get; set; }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            RequestType = "exit-status";
            WantReply = false;

            base.SerializePacketInternal(writer);

            writer.Write(ExitStatus);
        }
    }
}
