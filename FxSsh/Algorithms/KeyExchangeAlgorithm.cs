using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public abstract class KeyExchangeAlgorithm
    {
        protected HashAlgorithm hashAlgorithm;

        public abstract byte[] CreateKeyExchange();

        public abstract byte[] DecryptKeyExchange(byte[] exchangeData);

        public byte[] ComputeHash(byte[] input)
        {
            return hashAlgorithm.ComputeHash(input);
        }
    }
}