using System;
using System.Linq;
using System.Text;

namespace FxSsh.Messages.Userauth
{
    public class PublicKeyRequestMessage : RequestMessage
    {
        public PublicKeyRequestMessage()
        {
            MethodName = "publickey";
        }

        public bool HasSignature { get; set; }
        public string KeyAlgorithmName { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] Signature { get; set; }

        public byte[] PayloadWithoutSignature { get; private set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            if (MethodName != "publickey")
                throw new ArgumentException($"Method name {MethodName} is not valid.");

            HasSignature = reader.ReadBoolean();
            KeyAlgorithmName = reader.ReadString(Encoding.ASCII);
            PublicKey = reader.ReadBinary();

            if (HasSignature)
            {
                Signature = reader.ReadBinary();
                PayloadWithoutSignature = RawBytes.Take(RawBytes.Length - Signature.Length - 4).ToArray();
            }
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            base.SerializePacketInternal(writer);

            writer.Write(HasSignature);
            writer.Write(KeyAlgorithmName, Encoding.ASCII);
            writer.WriteBinary(PublicKey);

            if (HasSignature)
                writer.WriteBinary(Signature);
        }
    }
}