using System;
using FxSsh.Util;

namespace FxSsh.Messages.Connection
{
    public class SessionOpenMessage : ChannelOpenMessage
    {
        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            if (ChannelType != "session")
                throw new ArgumentException($"Channel type {ChannelType} is not valid.");
        }
    }
}