using System;
using System.Collections.Generic;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services.Userauth
{
    public abstract class NoneMethod : IMethod
    {
        public const string MethodName = "none";
        
        public string GetName() => MethodName;
        public IReadOnlyDictionary<byte, Type> UsedMessageTypes() => new Dictionary<byte, Type>();
        public Type RequestType() => typeof(NoneRequest);
        public abstract bool IsUsable();
    }

    public sealed class NoneClientMethod : NoneMethod, IClientMethod
    {
        private ClientSession _session;
        private string _username;
        private string _serviceName;
        private bool _used = false;
        
        public void Configure(ClientSession session, string username, string serviceName)
        {
            _session = session;
            _username = username;
            _serviceName = serviceName;
        }

        public void InitiateAuth()
        {
            _used = true;
            _session.SendMessage(new RequestMessage
            {
                MethodName = "none",
                Username = _username,
                ServiceName = _serviceName
            });
        }

        public override bool IsUsable() => !_used;
    }

    public sealed class NoneServerMethod : NoneMethod, IServerMethod
    {
        private ServerSession _session;
        private Action<AuthInfo> _succeed;
        private Action<(AuthInfo auth, bool partial)> _failed;

        public void Configure(ServerSession session, Action<AuthInfo> succeedCallback, Action<(AuthInfo auth, bool partial)> failedCallback)
        {
            _session = session;
            _succeed = succeedCallback;
            _failed = failedCallback;
        }

        private void HandleMessage(NoneRequest message)
        {
            var args = new AuthInfo
            {
                Service = message.ServiceName,
                Username = message.Username
            };
            
            _succeed(args);
        }

        public override bool IsUsable() => false;
    }
}