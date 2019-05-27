﻿using System;

namespace FxSsh.Messages.Userauth
{
    [Message("SSH_MSG_USERAUTH_SUCCESS", MessageNumber)]
    public class SuccessMessage : UserauthServiceMessage
    {
        public const byte MessageNumber = 52;

        public override byte MessageType { get { return MessageNumber; } }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
        }
    }
}
