using FxSsh.Services.Userauth.Client;

namespace FxSsh.Services
{
    public class KnownPasswordAuthHandler : IPasswordAuthHandler
    {
        private readonly string _password;

        public KnownPasswordAuthHandler(string password)
        {
            _password = password;
        }
        
        public bool IsRetryable() => false;
        public string GetPassword() => _password;
        public string ChangePassword(string prompt, string language) => null;
    }
}