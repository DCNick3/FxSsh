using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class DiffieHellmanGroupSha1 : KeyExchangeAlgorithm
    {
        private readonly DiffieHellman _exchangeAlgorithm;

        public DiffieHellmanGroupSha1(DiffieHellman algorithm)
        {
            _exchangeAlgorithm = algorithm;
            hashAlgorithm = new SHA1CryptoServiceProvider();
        }

        public override byte[] CreateKeyExchange()
        {
            return _exchangeAlgorithm.CreateKeyExchange();
        }

        public override byte[] DecryptKeyExchange(byte[] exchangeData)
        {
            return _exchangeAlgorithm.DecryptKeyExchange(exchangeData);
        }
    }
}