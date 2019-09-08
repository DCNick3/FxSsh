using System;
using System.Collections.Generic;
using FxSsh.Messages;
using FxSsh.Transport;
using FxSsh.Util;

namespace FxSsh.Services.Userauth
{
    public abstract class UserauthService : ISshService, IMessageHandler
    {
        public const string ServiceName = "ssh-userauth";
        protected IMethod CurrentMethod;
        private IReadOnlyDictionary<byte, Type> _currentMethodSpecificMessages = new Dictionary<byte, Type>();
        // ReSharper disable once NotAccessedField.Local
        private Session _session;

        public UserauthService(Session session)
        {
            _session = session;
        }

        public void CloseService()
        {
        }

        public virtual void HandleMessageCore(Message message)
        {
            if (_currentMethodSpecificMessages.ContainsKey(message.MessageType))
                CurrentMethod.InvokeHandleMessage(message);
            else
                this.InvokeHandleMessage((UserauthServiceMessage) message);
        }

        protected virtual void UseUserauthMethod(IMethod method)
        {
            // Maybe we should inform _currentUserauthMethod that it is no longer needed? Hmm...
            CurrentMethod = method;
            _currentMethodSpecificMessages = CurrentMethod?.UsedMessageTypes() ?? new Dictionary<byte, Type>();
        }

        public Message CreateMethodSpecificMessage(byte number)
        {
            if (_currentMethodSpecificMessages.TryGetValue(number, out var type))
                return (Message) Activator.CreateInstance(type);
            
            return new UnknownMessage();
        }
    }
}