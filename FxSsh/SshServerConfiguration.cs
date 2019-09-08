using System.Net;

namespace FxSsh
{
    public class SshServerConfiguration
    {
        public const int DefaultPort = 2222;

        public SshServerConfiguration()
            : this(IPAddress.IPv6Any, DefaultPort, "SSH-2.0-FxSsh")
        {
        }

        public SshServerConfiguration(IPAddress localAddress, int port, string serverBanner)
        {
            LocalAddress = localAddress;
            Port = port;
            ServerBanner = serverBanner;
        }

        public IPAddress LocalAddress { get; }
        public int Port { get; }

        public string ServerBanner { get; }
    }
}