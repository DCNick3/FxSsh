using System;

namespace FxSsh.Messages.Connection
{
    public class SessionOpenMessage : ChannelOpenMessage
    {
        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            if (ChannelType != "session")
                throw new ArgumentException(string.Format("Channel type {0} is not valid.", ChannelType));
        }
    }
}