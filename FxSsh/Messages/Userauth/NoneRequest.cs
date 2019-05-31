using FxSsh.Services.Userauth;

namespace FxSsh.Messages.Userauth
{
    public class NoneRequest : RequestMessage
    {
        public NoneRequest()
        {
            MethodName = NoneUserauthMethod.MethodName;
        }
    }
}