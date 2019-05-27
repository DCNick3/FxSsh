namespace FxSsh.Messages
{
    [Message("SSH_MSG_UNIMPLEMENTED", MessageNumber)]
    public class UnimplementedMessage : Message
    {
        public const byte MessageNumber = 3;
        
        public uint SequenceNumber { get; set; }
        
        public override byte MessageType { get { return MessageNumber; } }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            SequenceNumber = reader.ReadUInt32();
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(SequenceNumber);
        }
    }
}