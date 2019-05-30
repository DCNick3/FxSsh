using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace FxSsh.Algorithms
{
    public class Ed25519Key : PublicKeyAlgorithm
    {
        private readonly Ed25519 _algorithm = new Ed25519();
        private Key _privateKey;
        private PublicKey _publicKey;
        public override string Name => "ssh-ed25519";

        private void GenerateKey()
        {
            _privateKey = new Key(_algorithm,
                new KeyCreationParameters
                {
                    ExportPolicy = KeyExportPolicies.AllowPlaintextExport | KeyExportPolicies.AllowPlaintextArchiving
                });
            _publicKey = _privateKey.PublicKey;
        }

        public override PublicKeyAlgorithm ImportInternalBlob(byte[] bytes)
        {
            _privateKey = Key.Import(_algorithm, bytes, KeyBlobFormat.RawPrivateKey);
            _publicKey = _privateKey.PublicKey;
            return this;
        }

        public override PublicKeyAlgorithm ImportKeyAndCertificatesData(byte[] data)
        {
            using (var worker = new SshDataWorker(data))
            {
                if (worker.ReadString(Encoding.ASCII) != Name)
                    throw new CryptographicException("Key and certificates were not created with this algorithm.");

                var pubKey = worker.ReadBinary();
                _privateKey = null;
                _publicKey = PublicKey.Import(_algorithm, pubKey, KeyBlobFormat.RawPublicKey);
            }

            return this;
        }

        public override byte[] ExportInternalBlob()
        {
            if (_privateKey == null)
                GenerateKey();

            return _privateKey.Export(KeyBlobFormat.RawPrivateKey);
        }

        public override byte[] ExportKeyAndCertificatesData()
        {
            if (_publicKey == null)
                GenerateKey();

            using (var worker = new SshDataWorker())
            {
                worker.Write(Name, Encoding.ASCII);
                worker.Write(_publicKey.Export(KeyBlobFormat.RawPublicKey));

                return worker.ToByteArray();
            }
        }

        public override bool VerifyData(byte[] data, byte[] signature)
        {
            return _algorithm.Verify(_publicKey, data, signature);
        }

        public override byte[] SignData(byte[] data)
        {
            if (_privateKey == null)
                throw new CryptographicException("No private key");

            return _algorithm.Sign(_privateKey, data);
        }
    }
}