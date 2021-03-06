﻿using System.ComponentModel;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class EncryptionAlgorithm
    {
        private readonly SymmetricAlgorithm _algorithm;
        private readonly CipherModeEx _mode;
        private readonly ICryptoTransform _transform;

        public EncryptionAlgorithm(SymmetricAlgorithm algorithm, int keySize, CipherModeEx mode, byte[] key, byte[] iv,
            bool isEncryption)
        {
            algorithm.KeySize = keySize;
            algorithm.Key = key;
            algorithm.IV = iv;
            algorithm.Padding = PaddingMode.None;

            _algorithm = algorithm;
            _mode = mode;

            _transform = CreateTransform(isEncryption);
        }

        public int BlockBytesSize => _algorithm.BlockSize >> 3;

        public byte[] Transform(byte[] input)
        {
            var output = new byte[input.Length];
            _transform.TransformBlock(input, 0, input.Length, output, 0);
            return output;
        }

        private ICryptoTransform CreateTransform(bool isEncryption)
        {
            switch (_mode)
            {
                case CipherModeEx.CBC:
                    _algorithm.Mode = CipherMode.CBC;
                    return isEncryption
                        ? _algorithm.CreateEncryptor()
                        : _algorithm.CreateDecryptor();
                case CipherModeEx.CTR:
                    return new CtrModeCryptoTransform(_algorithm);
                default:
                    throw new InvalidEnumArgumentException($"Invalid mode: {_mode}");
            }
        }
    }
}