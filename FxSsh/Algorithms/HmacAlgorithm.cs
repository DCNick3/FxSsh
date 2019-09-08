using System.Linq;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class HmacAlgorithm
    {
        private readonly KeyedHashAlgorithm _algorithm;

        public HmacAlgorithm(KeyedHashAlgorithm algorithm, int digestLength, byte[] key)
        {
            DigestLength = digestLength;
            _algorithm = algorithm;
            _algorithm.Key = key;
        }

        public int DigestLength { get; }

        public byte[] ComputeHash(byte[] input)
        {
            return _algorithm.ComputeHash(input).Take(DigestLength).ToArray();
        }
    }
}