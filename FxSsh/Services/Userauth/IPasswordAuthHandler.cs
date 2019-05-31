namespace FxSsh.Services.Userauth
{
    public interface IPasswordAuthHandler
    {
        bool IsRetryable();
        string GetPassword();
        string ChangePassword(string prompt, string language);
    }
}