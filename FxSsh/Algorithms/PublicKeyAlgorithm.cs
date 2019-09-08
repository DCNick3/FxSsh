using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using FxSsh.Util;

namespace FxSsh.Algorithms
{
    public abstract class PublicKeyAlgorithm
    {
        public abstract string Name { get; }
        
        /// <summary>
        /// Specifies whether algorithm instance contains only public key 
        /// </summary>
        public abstract bool PublicOnly { get; }
        public string GetFingerprint(FingerprintType type = FingerprintType.Sha256)
        {
            using (var hash = HashAlgorithm.Create(type.ToString().ToUpper()))
            {
                Debug.Assert(hash != null, "Invalid hash algorithm");
                var bytes = hash.ComputeHash(ExportKeyAndCertificatesData());
                switch (type)
                {
                    case FingerprintType.Md5:
                        return BitConverter.ToString(bytes).Replace('-', ':');
                    case FingerprintType.Sha256:
                        return Convert.ToBase64String(bytes).Replace("=", "");
                    default:
                        throw new ArgumentOutOfRangeException(nameof(type), type, "must be Md5 or Sha256");
                }
            }
        }

        public byte[] CreateSignature(byte[] data)
        {
            using (var worker = new SshDataWorker())
            {
                var rawSignature = CreateRawSignature(data);

                worker.Write(Name, Encoding.ASCII);
                worker.Write(rawSignature);

                return worker.ToByteArray();
            }
        }

        public bool VerifySignature(byte[] data, byte[] signature)
        {
            using (var worker = new SshDataWorker(signature))
            {
                var name = worker.ReadString(Encoding.ASCII);
                var rawSignature = worker.ReadBinary();
                
                if (name != Name)
                    throw new ArgumentException("was not created by this algorithm", nameof(signature));

                return VerifyRawSignature(data, rawSignature);
            }
        }

        /// <summary>
        /// Imports key blob, including private key
        /// </summary>
        /// <param name="bytes">Previously exported key blob</param>
        public abstract PublicKeyAlgorithm ImportInternalBlob(byte[] bytes);

        /// <summary>
        /// Import public key data, structured as per ssh RFC
        /// </summary>
        /// <param name="data">Key and certificate data, as per ssh RFC</param>
        public abstract PublicKeyAlgorithm ImportKeyAndCertificatesData(byte[] data);

        /// <summary>
        /// Exports key blob, including private key
        /// </summary>
        /// <returns>Opaque blob, </returns>
        public abstract byte[] ExportInternalBlob();

        /// <summary>
        /// Exports public key, structured as per ssh RFC
        /// </summary>
        /// <returns>Public key, structured as per ssh RFC</returns>
        public abstract byte[] ExportKeyAndCertificatesData();

        protected abstract bool VerifyRawSignature(byte[] data, byte[] signature);

        protected abstract byte[] CreateRawSignature(byte[] data);

        public enum FingerprintType
        {
            Md5,
            Sha256
        }
    }
}