namespace FxSsh.Services.Userauth.Server
{
    // TODO: How much of this higher-level services may REALLY need?
    /// <summary>
    /// Gives some information about successful authentication result to another services
    /// </summary>
    public class AuthInfo
    {
        // ReSharper disable once UnusedAutoPropertyAccessor.Global
        public string Username { get; set; }
        public string Service { get; set; }
    }
}