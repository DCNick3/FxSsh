using FxSsh.Messages.Userauth;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Client
{
    public sealed class NoneClientMethod : NoneMethod, IClientMethod
    {
        private ClientSession _session;
        private string _username;
        private string _serviceName;
        private bool _used;
        
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
}