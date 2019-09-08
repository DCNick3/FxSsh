using System.Linq;
using FxSsh.Algorithms;
using FxSsh.Messages.Userauth;
using FxSsh.Transport;
using FxSsh.Util;

namespace FxSsh.Services.Userauth.Client
{
    public class PublicKeyClientMethod : PublicKeyMethod, IClientMethod
    {
        private readonly PublicKeyAlgorithm _key;
        private ClientSession _session;
        private string _username;
        private string _serviceName;
        private bool _used;

        public PublicKeyClientMethod(PublicKeyAlgorithm key)
        {
            key.EnsureHasPrivate();
            
            _key = key;
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
            _session.SendMessage(new PublicKeyRequestMessage
            {
                Username = _username,
                ServiceName = _serviceName,
                KeyAlgorithmName = _key.Name,
                PublicKey = _key.ExportKeyAndCertificatesData(),
                HasSignature = false,
            });
        }

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(PublicKeyOkMessage message)
        {
            if (!message.PublicKey.SequenceEqual(_key.ExportKeyAndCertificatesData()))
                throw new SshConnectionException("Server accepted not the offered key", DisconnectReason.ProtocolError);
            
            
            var request = new PublicKeyRequestMessage
            {
                Username = _username,
                ServiceName = _serviceName,
                KeyAlgorithmName = _key.Name,
                PublicKey = _key.ExportKeyAndCertificatesData(),
                HasSignature = true
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