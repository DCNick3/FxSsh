using System.Diagnostics.Contracts;
using FxSsh.Messages;
using FxSsh.Messages.Userauth;

namespace FxSsh.Services
{
    public abstract class UserauthService : ISshService, IDynamicInvoker
    {
        protected string _currentAuthMethod;
        private Session _session;

        public UserauthService(Session session)
        {
            _session = session;
        }

        public void CloseService()
        {
        }

        public void HandleMessageCore(Message message)
        {
            Contract.Requires(message != null);

            this.InvokeHandleMessage((UserauthServiceMessage) message);
        }

        public Message CreateMethodSpecificMessage(byte number)
        {
            switch (_currentAuthMethod)
            {
                case "publickey":
                    if (number == PublicKeyOkMessage.MessageNumber)
                        return new PublicKeyOkMessage();
                    break;
                case "password":
                    if (number == PasswordChangeRequestMessage.MessageNumber)
                        return new PasswordChangeRequestMessage();
                    break;
            }

            return new UnknownMessage();
        }
    }
}