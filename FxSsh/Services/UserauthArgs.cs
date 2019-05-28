using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class UserauthArgs
    {
        public UserauthArgs(Session session, string username, string keyAlgorithm, string fingerprint, byte[] key)
        {
            Contract.Requires(keyAlgorithm != null);
            Contract.Requires(fingerprint != null);
            Contract.Requires(key != null);

            AuthMethod = "publickey";
            KeyAlgorithm = keyAlgorithm;
            Fingerprint = fingerprint;
            Key = key;
            Session = session;
            Username = username;
        }

        public UserauthArgs(Session session, string username, string password)
        {
            Contract.Requires(username != null);
            Contract.Requires(password != null);

            AuthMethod = "password";
            Username = username;
            Password = password;
            Session = session;
        }

        public string AuthMethod { get; }
        public Session Session { get; }
        public string Username { get; }
        public string Password { get; }
        public string KeyAlgorithm { get; }
        public string Fingerprint { get; }
        public byte[] Key { get; }
        public bool Result { get; set; }
    }
}