using System;
using FxSsh.Messages;

namespace FxSsh.Services.Userauth
{
    /// <summary>
    /// Helper class that wraps <see cref="IServerMethod"/>
    /// </summary>
    public sealed class ServerMethod
    {
        private readonly IServerMethod _method;

        public bool Usable => !Succeed && _method.IsUsable();
        public string Name => _method.GetName();
        public Type RequestType => _method.RequestType();
        public bool Succeed { get; private set; }

        public void InvokeHandleMessage(Message message)
        {
            _method.InvokeHandleMessage(message);
        }

        public ServerMethod(ServerSession session, IServerMethod realMethod)
        {
            _method = realMethod;
            _method.Configure(session, info => OnSuccess?.Invoke(this, info),
                args => OnFailure?.Invoke(this, args));

            OnSuccess += (a, b) => Succeed = true;
        }

        public event EventHandler<(AuthInfo auth, bool partial)> OnFailure;
        public event EventHandler<AuthInfo> OnSuccess;
    }
}