﻿using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_CHANNEL_OPEN_FAILURE", MessageNumber)]
    public class ChannelOpenFailureMessage : ConnectionServiceMessage
    {
        public const byte MessageNumber = 92;

        public uint RecipientChannel { get; set; }
        public ChannelOpenFailureReason ReasonCode { get; set; }
        public string Description { get; set; }
        // ReSharper disable once UnusedAutoPropertyAccessor.Global
        public string Language { get; set; }

        public override byte MessageType => MessageNumber;

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            writer.Write(RecipientChannel);
            writer.Write((uint) ReasonCode);
            writer.Write(Description, Encoding.ASCII);
            writer.Write(Language ?? "en", Encoding.ASCII);
        }
    }
}