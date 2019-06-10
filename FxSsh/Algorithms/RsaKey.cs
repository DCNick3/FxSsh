using System.Security.Cryptography;
using System.Text;

namespace FxSsh.Algorithms
{
    public class RsaKey : PublicKeyAlgorithm
    {
        private readonly RSACryptoServiceProvider _algorithm = new RSACryptoServiceProvider();

        public override string Name => "ssh-rsa";
        public override bool PublicOnly => _algorithm.PublicOnly;

        public override PublicKeyAlgorithm ImportInternalBlob(byte[] bytes)
        {
            _algorithm.ImportCspBlob(bytes);
            return this;
        }

        public override byte[] ExportInternalBlob()
        {
            return _algorithm.ExportCspBlob(true);
        }

        public override PublicKeyAlgorithm ImportKeyAndCertificatesData(byte[] data)
        {
            using (var worker = new SshDataWorker(data))
            {
                if (worker.ReadString(Encoding.ASCII) != Name)
                    throw new CryptographicException("Key and certificates were not created with this algorithm.");

                var args = new RSAParameters();
                args.Exponent = worker.ReadMpint();
                args.Modulus = worker.ReadMpint();

                _algorithm.ImportParameters(args);
            }

            return this;
        }

        public override byte[] ExportKeyAndCertificatesData()
        {
            using (var worker = new SshDataWorker())
            {
                var args = _algorithm.ExportParameters(false);

                worker.Write(Name, Encoding.ASCII);
                worker.WriteMpint(args.Exponent);
                worker.WriteMpint(args.Modulus);

                return worker.ToByteArray();
            }
        }

        public override bool VerifyData(byte[] data, byte[] signature)
        {
            return _algorithm.VerifyData(data, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }

        public override byte[] SignData(byte[] data)
        {
            return _algorithm.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }
    }
}