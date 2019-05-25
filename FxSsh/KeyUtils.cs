using FxSsh.Algorithms;
using System;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;

namespace FxSsh
{
    public static class KeyUtils
    {
        private static PublicKeyAlgorithm GetKeyAlgorithm(string type)
        {
            Contract.Requires(type != null);

            switch (type)
            {
                case "ssh-rsa":
                    return new RsaKey();
                case "ssh-dss":
                    return new DssKey();
                default:
                    throw new ArgumentOutOfRangeException("type");
            }
        }

        public static string GeneratePrivateKey(string type)
        {
            Contract.Requires(type != null);

            var alg = GetKeyAlgorithm(type);
            var bytes = alg.ExportCspBlob();
            return Convert.ToBase64String(bytes);
        }

        public static string[] SupportedAlgorithms
        {
            get { return new string[] { "ssh-rsa", "ssh-dss" }; }
        }
    }
}
