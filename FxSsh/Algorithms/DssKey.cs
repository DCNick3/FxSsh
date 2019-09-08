using System.Security.Cryptography;
using System.Text;
using FxSsh.Util;

namespace FxSsh.Algorithms
{
    public class DssKey : PublicKeyAlgorithm
    {
        private readonly DSACryptoServiceProvider _algorithm = new DSACryptoServiceProvider();

        public override string Name => "ssh-dss";
        public override bool PublicOnly => _algorithm.PublicOnly;

        public override PublicKeyAlgorithm ImportInternalBlob(byte[] bytes)
        {
            _algorithm.ImportCspBlob(bytes);

            return this;
        }

        public override PublicKeyAlgorithm ImportKeyAndCertificatesData(byte[] data)
        {
            using (var worker = new SshDataWorker(data))
            {
                if (worker.ReadString(Encoding.ASCII) != Name)
                    throw new CryptographicException("Key and certificates were not created with this algorithm.");

                var args = new DSAParameters();
                args.P = worker.ReadMpint();
                args.Q = worker.ReadMpint();
                args.G = worker.ReadMpint();
                args.Y = worker.ReadMpint();

                _algorithm.ImportParameters(args);
            }

            return this;
        }

        public override byte[] ExportInternalBlob()
        {
            return _algorithm.ExportCspBlob(true);
        }

        public override byte[] ExportKeyAndCertificatesData()
        {
            using (var worker = new SshDataWorker())
            {
                var args = _algorithm.ExportParameters(false);

                worker.Write(Name, Encoding.ASCII);
                worker.WriteMpint(args.P);
                worker.WriteMpint(args.Q);
                worker.WriteMpint(args.G);
                worker.WriteMpint(args.Y);

                return worker.ToByteArray();
            }
        }

        protected override bool VerifyRawSignature(byte[] data, byte[] signature)
        {
            return _algorithm.VerifyData(data, signature);
        }

        protected override byte[] CreateRawSignature(byte[] data)
        {
            return _algorithm.SignData(data);
        }
    }
}