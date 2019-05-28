using System.Diagnostics.Contracts;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class CtrModeCryptoTransform : ICryptoTransform
    {
        private readonly SymmetricAlgorithm _algorithm;
        private readonly byte[] _block;
        private readonly byte[] _iv;
        private readonly ICryptoTransform _transform;


        public CtrModeCryptoTransform(SymmetricAlgorithm algorithm)
        {
            Contract.Requires(algorithm != null);

            algorithm.Mode = CipherMode.ECB;
            algorithm.Padding = PaddingMode.None;

            _algorithm = algorithm;
            _transform = algorithm.CreateEncryptor();
            _iv = algorithm.IV;
            _block = new byte[algorithm.BlockSize >> 3];
        }

        public bool CanReuseTransform => true;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => _algorithm.BlockSize;

        public int OutputBlockSize => _algorithm.BlockSize;

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
            int outputOffset)
        {
            var written = 0;
            var bytesPerBlock = InputBlockSize >> 3;

            for (var i = 0; i < inputCount; i += bytesPerBlock)
            {
                written += _transform.TransformBlock(_iv, 0, bytesPerBlock, _block, 0);

                for (var j = 0; j < bytesPerBlock; j++)
                    outputBuffer[outputOffset + i + j] = (byte) (_block[j] ^ inputBuffer[inputOffset + i + j]);

                var k = _iv.Length;
                while (--k >= 0 && ++_iv[k] == 0) ;
            }

            return written;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var output = new byte[inputCount];
            TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
            return output;
        }

        public void Dispose()
        {
            _transform.Dispose();
        }
    }
}