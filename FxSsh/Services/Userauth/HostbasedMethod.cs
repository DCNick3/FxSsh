using System;
using System.Collections.Generic;
using FxSsh.Algorithms;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services.Userauth
{
    public abstract class HostbasedMethod : IMethod
    {
        public const string MethodName = "hostbased";
        
        public string GetName() => MethodName;
        public IReadOnlyDictionary<byte, Type> UsedMessageTypes() => new Dictionary<byte, Type>();
        public Type RequestType() => typeof(HostbasedRequestMessage);
        public abstract bool IsUsable();
    }

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

                request.Signature = _key.CreateSignatureData(worker.ToByteArray());
            }
                
            _session.SendMessage(request);
        }
    }

    public abstract class HostbasedServerMethod : HostbasedMethod, IServerMethod
    {
        private Action<AuthInfo> _succeed;
        private Action<(AuthInfo auth, bool partial)> _failed;
        protected ServerSession Session;

        public override bool IsUsable()
        {
            return true;
        }

        public void Configure(ServerSession session, Action<AuthInfo> succeedCallback, Action<(AuthInfo auth, bool partial)> failedCallback)
        {
            Session = session;
            _succeed = succeedCallback;
            _failed = failedCallback;
        }

        protected abstract bool CheckHost(string username, string serviceName, string hostname, string hostUsername,
            PublicKeyAlgorithm key);

        protected void HandleMessage(HostbasedRequestMessage message)
        {
            var args = new AuthInfo
            {
                Service = message.ServiceName,
                Username = message.Username
            };
            
            var key = FxSsh.Session._publicKeyAlgorithms[message.PublicKeyAlgorithm].FromKeyAndCertificatesData(message.KeyAndCertificatesData);

            var valid = CheckHost(message.Username, message.ServiceName, message.ClientName, message.HostUsername,
                key);

            if (!valid)
            {
                _failed((args, false));
                return;
            }

            using (var worker = new SshDataWorker())
            {
                worker.Write(Session.SessionId);
                worker.WriteRawBytes(message.PayloadWithoutSignature);

                valid = key.VerifyData(worker.ToByteArray(), key.GetSignature(message.Signature));
            }

            if (valid)
                _succeed(args);
            else
                _failed((args, false));
        }
    }
}