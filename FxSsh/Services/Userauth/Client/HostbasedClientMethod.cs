using FxSsh.Algorithms;
using FxSsh.Messages.Userauth;
using FxSsh.Transport;
using FxSsh.Util;

namespace FxSsh.Services.Userauth.Client
{
    public sealed class HostbasedClientMethod : HostbasedMethod, IClientMethod
    {
        private readonly PublicKeyAlgorithm _key;
        private readonly string _hostname;
        private readonly string _localUsername;
        private bool _used;
        private ClientSession _session;
        private string _username;
        private string _serviceName;

        public HostbasedClientMethod(PublicKeyAlgorithm key, string hostname, string localUsername)
        {
            key.EnsureHasPrivate();

            _key = key;
            _hostname = hostname;
            _localUsername = localUsername;
        }
        
        public override bool IsUsable() => !_used;

        public void Configure(ClientSession session, string username, string serviceName)
        {
            _session = session;
            _username = username;
            _serviceName = serviceName;
        }

        public void InitiateAuth()
        {
            _used = true;
            
            
            var request = new HostbasedRequestMessage
            {
                Username = _username,
                ServiceName = _serviceName,
                ClientName = _hostname,
                HostUsername = _localUsername,
                PublicKeyAlgorithm = _key.Name,
                KeyAndCertificatesData = _key.ExportKeyAndCertificatesData(),
            };

            using (var worker = new SshDataWorker())
            {
                worker.Write(_session.SessionId);
                worker.WriteRawBytes(request.SerializePacket());

                request.Signature = _key.CreateSignature(worker.ToByteArray());
            }
                
            _session.SendMessage(request);
        }
    }
}