using FxSsh.Services.Userauth.Server;

namespace FxSsh.Services.Connection
{
    public class TcpRequestArgs
    {
        public TcpRequestArgs(SessionChannel channel, string host, int port, string originatorIp, int originatorPort,
            AuthInfo authInfo)
        {
            Channel = channel;
            Host = host;
            Port = port;
            OriginatorIp = originatorIp;
            OriginatorPort = originatorPort;
            AttachedAuthInfo = authInfo;
        }

        public SessionChannel Channel { get; }
        public string Host { get; }
        public int Port { get; }
        public string OriginatorIp { get; }
        public int OriginatorPort { get; }
        // ReSharper disable once UnusedAutoPropertyAccessor.Global
        public AuthInfo AttachedAuthInfo { get; }
    }
}