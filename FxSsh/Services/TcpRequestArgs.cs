using System.Diagnostics.Contracts;
using FxSsh.Services.Userauth;

namespace FxSsh.Services
{
    public class TcpRequestArgs
    {
        public TcpRequestArgs(SessionChannel channel, string host, int port, string originatorIP, int originatorPort,
            AuthInfo authInfo)
        {
            Contract.Requires(channel != null);
            Contract.Requires(host != null);
            Contract.Requires(originatorIP != null);

            Channel = channel;
            Host = host;
            Port = port;
            OriginatorIP = originatorIP;
            OriginatorPort = originatorPort;
            AttachedAuthInfo = authInfo;
        }

        public SessionChannel Channel { get; }
        public string Host { get; }
        public int Port { get; }
        public string OriginatorIP { get; }
        public int OriginatorPort { get; }
        public AuthInfo AttachedAuthInfo { get; }
    }
}