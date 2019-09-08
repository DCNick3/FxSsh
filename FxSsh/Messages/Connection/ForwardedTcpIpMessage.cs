using System;
using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages.Connection
{
    public class ForwardedTcpIpMessage : ChannelOpenMessage
    {
        public string Address { get; private set; }
        public uint Port { get; private set; }
        public string OriginatorIpAddress { get; private set; }
        public uint OriginatorPort { get; private set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            if (ChannelType != "forwarded-tcpip")
                throw new ArgumentException($"Channel type {ChannelType} is not valid.");

            Address = reader.ReadString(Encoding.ASCII);
            Port = reader.ReadUInt32();
            OriginatorIpAddress = reader.ReadString(Encoding.ASCII);
            OriginatorPort = reader.ReadUInt32();
        }
    }
}