using System;
using System.Collections.Generic;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services.Userauth
{
    public abstract class PasswordMethod : IMethod
    {
        public const string MethodName = "password";
        public string GetName() => MethodName;
        public IReadOnlyDictionary<byte, Type> UsedMessageTypes() =>
            new Dictionary<byte, Type>
            {
                {PasswordChangeRequestMessage.MessageNumber, typeof(PasswordChangeRequestMessage)}
            };

        public Type RequestType() => typeof(PasswordRequestMessage);
        public abstract bool IsUsable();
    }

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

    public abstract class PasswordServerMethod : PasswordMethod, IServerMethod
    {
        protected ServerSession Session;
        private Action<AuthInfo> _succeed;
        private Action<(AuthInfo auth, bool partial)> _failed;

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

        protected abstract bool CheckPassword(string username, string serviceName, string password);
        
        protected void HandleMessage(PasswordRequestMessage message)
        {
            var auth = new AuthInfo
            {
                Username = message.Username,
                Service = message.ServiceName
            };

            if (CheckPassword(message.Username, message.ServiceName, message.Password))
                _succeed(auth);
            else
                _failed((auth, false));
        }
    }
}