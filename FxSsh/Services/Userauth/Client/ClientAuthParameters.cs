using System;
using System.Collections.Generic;

namespace FxSsh.Services.Userauth.Client
{
    /// <summary>
    /// Specifies how ssh client should authenticate to server
    /// </summary>
    public class ClientAuthParameters
    {
        public string Username { get; set; }
        public string ServiceName { get; set; }
        public IReadOnlyList<IClientMethod> Methods { get; set; }
        public EventHandler<OnBannerEventArgs> OnBanner { get; set; }
    }
}