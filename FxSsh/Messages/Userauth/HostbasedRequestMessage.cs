using System;
using System.Linq;
using System.Text;

namespace FxSsh.Messages.Userauth
{
    public class HostbasedRequestMessage : RequestMessage
    {
        public HostbasedRequestMessage()
        {
            MethodName = "hostbased";
        }

        public string PublicKeyAlgorithm { get; set; }
        public byte[] KeyAndCertificatesData { get; set; }
        public string ClientName { get; set; }
        public string HostUsername { get; set; }
        public byte[] Signature { get; set; }

        public byte[] PayloadWithoutSignature { get; set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            if (MethodName != "hostbased")
                throw new ArgumentException($"Method name {MethodName} is not valid.");

            PublicKeyAlgorithm = reader.ReadString(Encoding.ASCII);
            KeyAndCertificatesData = reader.ReadBinary();
            ClientName = reader.ReadString(Encoding.ASCII);
            HostUsername = reader.ReadString(Encoding.UTF8);
            Signature = reader.ReadBinary();

            PayloadWithoutSignature = RawBytes.Take(RawBytes.Length - Signature.Length - 4).ToArray();
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            base.SerializePacketInternal(writer);

            writer.Write(PublicKeyAlgorithm, Encoding.ASCII);
            writer.WriteBinary(KeyAndCertificatesData);
            writer.Write(ClientName, Encoding.ASCII);
            writer.Write(HostUsername, Encoding.UTF8);

            if (Signature != null) // For ease of signing
                writer.WriteBinary(Signature);
        }
    }
}