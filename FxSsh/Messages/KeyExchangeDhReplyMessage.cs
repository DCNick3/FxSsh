using FxSsh.Util;

namespace FxSsh.Messages
{
    [Message("SSH_MSG_KEXDH_REPLY", MessageNumber)]
    public class KeyExchangeDhReplyMessage : Message
    {
        public const byte MessageNumber = 31;

        public byte[] HostKey { get; set; }
        public byte[] F { get; set; }
        public byte[] Signature { get; set; }

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            HostKey = reader.ReadBinary();
            F = reader.ReadMpint();
            Signature = reader.ReadBinary();
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(HostKey);
            writer.WriteMpint(F);
            writer.Write(Signature);
        }
    }
}