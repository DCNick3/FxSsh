using System;
using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages.Connection
{
    public class DirectTcpIpMessage : ChannelOpenMessage
    {
        public string Host { get; private set; }
        public uint Port { get; private set; }
        public string OriginatorIpAddress { get; private set; }
        public uint OriginatorPort { get; private set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            if (ChannelType != "direct-tcpip")
                throw new ArgumentException($"Channel type {ChannelType} is not valid.");

            Host = reader.ReadString(Encoding.ASCII);
            Port = reader.ReadUInt32();
            OriginatorIpAddress = reader.ReadString(Encoding.ASCII);
            OriginatorPort = reader.ReadUInt32();
        }
    }
}