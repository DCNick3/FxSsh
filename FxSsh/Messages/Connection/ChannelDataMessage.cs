﻿using FxSsh.Util;

namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_CHANNEL_DATA", MessageNumber)]
    public class ChannelDataMessage : ConnectionServiceMessage
    {
        public const byte MessageNumber = 94;

        public uint RecipientChannel { get; set; }
        public byte[] Data { get; set; }

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            RecipientChannel = reader.ReadUInt32();
            Data = reader.ReadBinary();
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(RecipientChannel);
            writer.Write(Data);
        }
    }
}