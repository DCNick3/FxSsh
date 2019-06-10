using System;
using System.Diagnostics.Contracts;
using FxSsh.Algorithms;

namespace FxSsh
{
    public static class KeyUtils
    {
        public static string[] SupportedAlgorithms => new[] {"ssh-rsa", "ssh-dss", "ssh-ed25519"};

        private static PublicKeyAlgorithm GetKeyAlgorithm(string type)
        {
            Contract.Requires(type != null);

            switch (type)
            {
                case "ssh-rsa":
                    return new RsaKey();
                case "ssh-dss":
                    return new DssKey();
                case "ssh-ed25519":
                    return new Ed25519Key();
                default:
                    throw new ArgumentOutOfRangeException(nameof(type));
            }
        }

        public static string GeneratePrivateKey(string type)
        {
            Contract.Requires(type != null);

            var alg = GetKeyAlgorithm(type);
            var bytes = alg.ExportInternalBlob();
            return Convert.ToBase64String(bytes);
        }

        public static void EnsureHasPrivate(this PublicKeyAlgorithm algorithm)
        {
            if (algorithm.PublicOnly)
                throw new ArgumentOutOfRangeException(nameof(algorithm), "must have private key");
        }
    }
}