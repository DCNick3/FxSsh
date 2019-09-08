using FxSsh.Messages.Userauth;
using FxSsh.Transport;

namespace FxSsh.Services.Userauth.Client
{
    public sealed class PasswordClientMethod : PasswordMethod, IClientMethod
    {
        private readonly IPasswordAuthHandler _passwordAuthHandler;
        private ClientSession _session;
        private string _username;
        private string _serviceName;
        private string _oldPassword;
        private bool _usable = true;
        
        public PasswordClientMethod(IPasswordAuthHandler passwordAuthHandler)
        {
            _passwordAuthHandler = passwordAuthHandler;
        }
        
        public override bool IsUsable() => _usable;

        public void Configure(ClientSession session, string username, string serviceName)
        {
            _session = session;
            _username = username;
            _serviceName = serviceName;
        }

        public void InitiateAuth()
        {
            if (!_passwordAuthHandler.IsRetryable())
                _usable = false;

            _oldPassword = _passwordAuthHandler.GetPassword();
            
            _session.SendMessage(new PasswordRequestMessage
            {
                Username = _username,
                ServiceName = _serviceName,
                Password = _oldPassword,
                IsPasswordUpdate = false
            });
        }

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(PasswordChangeRequestMessage message)
        {
            var newPassword = _passwordAuthHandler.ChangePassword(message.Prompt, message.Language);

            if (newPassword == null)
            {
                _usable = false;
                return;
                // TODO: Should call some "failed" event
            }
            
            _session.SendMessage(new PasswordRequestMessage
            {
                Username = _username,
                ServiceName = _serviceName,
                Password = _oldPassword,
                IsPasswordUpdate = true,
                NewPassword = newPassword
            });
        }

        public static PasswordClientMethod CreateKnownPassword(string password)
        {
            return new PasswordClientMethod(new KnownPasswordAuthHandler(password));
        }

        public static PasswordClientMethod CreateInteractive()
        {
            return new PasswordClientMethod(new InteractivePasswordAuthHandler());
        }
    }
}