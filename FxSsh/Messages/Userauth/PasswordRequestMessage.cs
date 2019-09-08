using System;
using System.Text;
using FxSsh.Util;

namespace FxSsh.Messages.Userauth
{
    public class PasswordRequestMessage : RequestMessage
    {
        public PasswordRequestMessage()
        {
            MethodName = "password";
        }

        public string Password { get; set; }
        public string NewPassword { get; set; }
        public bool IsPasswordUpdate { get; set; }

        protected override void LoadPacketInternal(SshDataWorker reader)
        {
            base.LoadPacketInternal(reader);

            if (MethodName != "password")
                throw new ArgumentException($"Method name {MethodName} is not valid.");

            IsPasswordUpdate = reader.ReadBoolean();
            Password = reader.ReadString(Encoding.UTF8);
            if (IsPasswordUpdate)
                NewPassword = reader.ReadString(Encoding.UTF8);
        }

        protected override void SerializePacketInternal(SshDataWorker writer)
        {
            base.SerializePacketInternal(writer);

            writer.Write(IsPasswordUpdate);
            writer.Write(Password, Encoding.UTF8);
            if (IsPasswordUpdate)
                writer.Write(NewPassword, Encoding.UTF8);
        }
    }
}