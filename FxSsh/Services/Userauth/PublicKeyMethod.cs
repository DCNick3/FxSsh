using System;
using System.Collections.Generic;
using System.Linq;
using FxSsh.Algorithms;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services.Userauth
{
    public abstract class PublicKeyMethod : IMethod
    {
        public const string MethodName = "publickey";
        
        public string GetName() => MethodName;

        public IReadOnlyDictionary<byte, Type> UsedMessageTypes() =>
            new Dictionary<byte, Type>
            {
                { PublicKeyOkMessage.MessageNumber, typeof(PublicKeyOkMessage) }
            };
        public Type RequestType() => typeof(PublicKeyRequestMessage);
        public abstract bool IsUsable();
    }

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

                request.Signature = _key.CreateSignatureData(worker.ToByteArray());
            }

            _session.SendMessage(request);
        }
    }

    public abstract class PublicKeyServerMethod : PublicKeyMethod, IServerMethod
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

        protected abstract bool CheckKey(string username, string serviceName, PublicKeyAlgorithm key);
            
        protected void HandleMessage(PublicKeyRequestMessage message)
        {
            var args = new AuthInfo
            {
                Service = message.ServiceName,
                Username = message.Username
            };
            
            var key = FxSsh.Session._publicKeyAlgorithms[message.KeyAlgorithmName].FromKeyAndCertificatesData(message.PublicKey);
            var valid = CheckKey(message.Username, message.ServiceName, key);

            if (!valid)
            {
                _failed((args, false));
                return;
            }

            if (!message.HasSignature)
            {
                Session.SendMessage(new PublicKeyOkMessage
                {
                    KeyAlgorithmName = message.KeyAlgorithmName,
                    PublicKey = message.PublicKey
                });
            }
            else
            {
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
}