﻿using System;

namespace FxSsh
{
    public class SshConnectionException : Exception
    {
        public SshConnectionException(string message, DisconnectReason disconnectReason = DisconnectReason.None)
            : base(message)
        {
            DisconnectReason = disconnectReason;
        }

        public DisconnectReason DisconnectReason { get; }

        public override string ToString()
        {
            return $"SSH connection disconnected because {DisconnectReason}";
        }
    }
}