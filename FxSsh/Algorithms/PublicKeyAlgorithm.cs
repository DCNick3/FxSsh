using System;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;
using System.Text;

namespace FxSsh.Algorithms
{
    [ContractClass(typeof(PublicKeyAlgorithmContract))]
    public abstract class PublicKeyAlgorithm
    {
        public abstract string Name { get; }

        public string GetFingerprint(string algo = "md5")
        {
            using (var hash = HashAlgorithm.Create(algo.ToUpper()))
            {
                Debug.Assert(hash != null, "Invalid hash algorithm");
                var bytes = hash.ComputeHash(ExportKeyAndCertificatesData());
                if (algo == "md5")
                    return BitConverter.ToString(bytes).Replace('-', ':');
                return Convert.ToBase64String(bytes);
            }
        }

        public byte[] GetSignature(byte[] signatureData)
        {
            Contract.Requires(signatureData != null);

            using (var worker = new SshDataWorker(signatureData))
            {
                if (worker.ReadString(Encoding.ASCII) != this.Name)
                    throw new CryptographicException("Signature was not created with this algorithm.");

                var signature = worker.ReadBinary();
                return signature;
            }
        }

        public byte[] CreateSignatureData(byte[] data)
        {
            Contract.Requires(data != null);

            using (var worker = new SshDataWorker())
            {
                var signature = SignData(data);

                worker.Write(this.Name, Encoding.ASCII);
                worker.WriteBinary(signature);

                return worker.ToByteArray();
            }
        }

        public abstract PublicKeyAlgorithm ImportCspBlob(byte[] bytes);

        public abstract PublicKeyAlgorithm ImportKeyAndCertificatesData(byte[] data);
        
        public abstract byte[] ExportCspBlob();

        public abstract byte[] ExportKeyAndCertificatesData();

        public abstract bool VerifyData(byte[] data, byte[] signature);

        public abstract bool VerifyHash(byte[] hash, byte[] signature);

        public abstract byte[] SignData(byte[] data);

        public abstract byte[] SignHash(byte[] hash);
    }
}
