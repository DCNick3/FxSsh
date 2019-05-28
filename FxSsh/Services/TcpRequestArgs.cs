using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class TcpRequestArgs
    {
        public TcpRequestArgs(SessionChannel channel, string host, int port, string originatorIP, int originatorPort,
            UserauthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(host != null);
            Contract.Requires(originatorIP != null);

            Channel = channel;
            Host = host;
            Port = port;
            OriginatorIP = originatorIP;
            OriginatorPort = originatorPort;
            AttachedUserauthArgs = userauthArgs;
        }

        public SessionChannel Channel { get; }
        public string Host { get; }
        public int Port { get; }
        public string OriginatorIP { get; }
        public int OriginatorPort { get; }
        public UserauthArgs AttachedUserauthArgs { get; }
    }
}