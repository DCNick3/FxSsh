namespace FxSsh.Messages.Userauth
{
    public class PasswordChangeRequestMessage : Message

    {
        public const byte MessageNumber = 60;

        public override byte MessageType => MessageNumber;
        
        
    }
}