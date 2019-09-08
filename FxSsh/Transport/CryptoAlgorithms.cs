using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using FxSsh.Algorithms;

namespace FxSsh.Transport
{
    // TODO: Should it be static? Making it part of config will allow library user to add their own algorithms 
    public static class CryptoAlgorithms
    {
        static CryptoAlgorithms()
        {
            KeyExchangeAlgorithms.Add("diffie-hellman-group1-sha1",
                new KeyExchange(() => new DiffieHellmanGroupSha1(new DiffieHellman(1024))));
            KeyExchangeAlgorithms.Add("diffie-hellman-group14-sha1",
                new KeyExchange(() => new DiffieHellmanGroupSha1(new DiffieHellman(2048))));

            PublicKeyAlgorithms.Add("ssh-rsa",
                new PublicKey(() => new RsaKey()));
            PublicKeyAlgorithms.Add("ssh-dss",
                new PublicKey(() => new DssKey()));
            PublicKeyAlgorithms.Add("ssh-ed25519",
                new PublicKey(() => new Ed25519Key()));
            
            EncryptionAlgorithms.Add("aes128-ctr",
                new Encryption(() => new AesCryptoServiceProvider(), 128, CipherModeEx.CTR));
            EncryptionAlgorithms.Add("aes192-ctr",
                new Encryption(() => new AesCryptoServiceProvider(), 192, CipherModeEx.CTR));
            EncryptionAlgorithms.Add("aes256-ctr",
                new Encryption(() => new AesCryptoServiceProvider(), 256, CipherModeEx.CTR));
            EncryptionAlgorithms.Add("aes128-cbc",
                new Encryption(() => new AesCryptoServiceProvider(), 128, CipherModeEx.CBC));
            EncryptionAlgorithms.Add("aes192-cbc",
                new Encryption(() => new AesCryptoServiceProvider(), 192, CipherModeEx.CBC));
            EncryptionAlgorithms.Add("aes256-cbc",
                new Encryption(() => new AesCryptoServiceProvider(), 256, CipherModeEx.CBC));
            EncryptionAlgorithms.Add("3des-cbc",
                new Encryption(() => new TripleDESCryptoServiceProvider(), 192, CipherModeEx.CBC));

            HmacAlgorithms.Add("hmac-md5", new Hmac(() => new HMACMD5(), 128, 128));
            HmacAlgorithms.Add("hmac-md5-96", new Hmac(() => new HMACMD5(), 128, 96));
            HmacAlgorithms.Add("hmac-sha1", new Hmac(() => new HMACSHA1(), 160, 160));
            HmacAlgorithms.Add("hmac-sha1-96", new Hmac(() => new HMACSHA1(), 160, 96));

            CompressionAlgorithms.Add("none", new Compression(() => new NoCompression()));
        }
        
        public static readonly Dictionary<string, KeyExchange> KeyExchangeAlgorithms = new Dictionary<string, KeyExchange>();
        public static readonly Dictionary<string, PublicKey> PublicKeyAlgorithms = new Dictionary<string, PublicKey>();
        public static readonly Dictionary<string, Encryption> EncryptionAlgorithms = new Dictionary<string, Encryption>();
        public static readonly Dictionary<string, Hmac> HmacAlgorithms = new Dictionary<string, Hmac>();
        public static readonly Dictionary<string, Compression> CompressionAlgorithms = new Dictionary<string, Compression>();

        public class Constructable<T>
        {
            private readonly Func<T> _constructor;

            public Constructable(Func<T> constructor)
            {
                _constructor = constructor;
            }

            public T Create() => _constructor();
        }

        public class KeyExchange : Constructable<KeyExchangeAlgorithm>
        {
            public KeyExchange(Func<KeyExchangeAlgorithm> constructor) : base(constructor)
            {}
        }
        public class PublicKey : Constructable<PublicKeyAlgorithm>
        {
            public PublicKey(Func<PublicKeyAlgorithm> constructor) : base(constructor)
            {}
            
            public PublicKeyAlgorithm CreateFromInternalBlob(byte[] blob) => Create().ImportInternalBlob(blob);

            public PublicKeyAlgorithm CreateFromKeyAndCertificatesData(byte[] keyAndCertificateData) =>
                Create().ImportKeyAndCertificatesData(keyAndCertificateData);
        }
        public class Encryption
        {
            private readonly Func<byte[], byte[], bool, EncryptionAlgorithm> _constructor;
            
            public Encryption(Func<SymmetricAlgorithm> algorithm, int keySize, CipherModeEx mode)
            {
                var algorithmInstance = algorithm();
                KeySize = keySize;
                BlockSize = algorithmInstance.BlockSize;
                _constructor = (key, vi, isEncryption) =>
                {
                    var algorithmInstanceInner = algorithm();
                    algorithmInstanceInner.KeySize = keySize;
                    return new EncryptionAlgorithm(algorithmInstanceInner, keySize, mode, key, vi, isEncryption);
                };
            }

            public int KeySize { get; }

            public int BlockSize { get; }

            public EncryptionAlgorithm Create(byte[] key, byte[] iv, bool isEncryption)
            {
                return _constructor(key, iv, isEncryption);
            }

            public EncryptionAlgorithm CreateEncryption(byte[] key, byte[] iv) => Create(key, iv, true);
            public EncryptionAlgorithm CreateDecryption(byte[] key, byte[] iv) => Create(key, iv, false);
        }
        public class Hmac
        {
            private readonly Func<byte[], HmacAlgorithm> _constructor;
            public Hmac(Func<KeyedHashAlgorithm> algorithm, int keySize, int digestSize)
            {
                KeySize = keySize;
                _constructor = key => new HmacAlgorithm(algorithm(), digestSize / 8, key);
            }
            public int KeySize { get; }
            public HmacAlgorithm Create(byte[] key) => _constructor(key);
        }
        public class Compression : Constructable<CompressionAlgorithm>
        {
            public Compression(Func<CompressionAlgorithm> constructor) : base(constructor)
            { }
        }
    }
}