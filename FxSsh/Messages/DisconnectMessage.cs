﻿using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages
{
    [Message("SSH_MSG_DISCONNECT", MessageNumber)]
    public class DisconnectMessage : Message
    {
        public const byte MessageNumber = 1;

        public DisconnectMessage(DisconnectReason reasonCode, string description = "", string language = "en")
        {
            ReasonCode = reasonCode;
            Description = description;
            Language = language;
        }

        public DisconnectReason ReasonCode { get; private set; }
        public string Description { get; private set; }
        public string Language { get; private set; }

        public override byte MessageType => MessageNumber;

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            ReasonCode = (DisconnectReason) reader.ReadUInt32();
            Description = reader.ReadString(Encoding.UTF8);
            if (reader.DataAvailable >= 4)
                Language = reader.ReadString(Encoding.UTF8);
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write((uint) ReasonCode);
            writer.Write(Description, Encoding.UTF8);
            writer.Write(Language ?? "en", Encoding.UTF8);
        }
    }
}