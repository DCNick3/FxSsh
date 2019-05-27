using System;

namespace FxSsh.Messages
{
    [Message("SSH_MSG_KEXDH_INIT", MessageNumber)]
    public class KeyExchangeDhInitMessage : Message
    {
        public const byte MessageNumber = 30;

        public byte[] E { get; set; }

        public override byte MessageType { get { return MessageNumber; } }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            E = reader.ReadMpint();
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.WriteMpint(E);
        }
    }
}
