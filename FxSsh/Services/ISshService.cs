using FxSsh.Messages;

namespace FxSsh.Services
{
    public interface ISshService
    {
        void HandleMessageCore(Message message);
        void CloseService();
    }
}