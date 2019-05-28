using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public abstract class SshService
    {
        protected internal readonly ServerSession _session;

        public SshService(ServerSession session)
        {
            Contract.Requires(session != null);

            _session = session;
        }

        protected internal abstract void CloseService();
    }
}