namespace FxSsh.Services.Userauth.Client
{
    public interface IPasswordAuthHandler
    {
        bool IsRetryable();
        string GetPassword();
        string ChangePassword(string prompt, string language);
    }
}