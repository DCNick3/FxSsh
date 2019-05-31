using System;
using System.Collections.Generic;

namespace FxSsh.Services.Userauth
{
    public class ClientAuthParameters
    {
        public string Username { get; set; }
        public string ServiceName { get; set; }
        public IReadOnlyList<IUserauthClientMethod> Methods { get; set; }
        public EventHandler<OnBannerEventArgs> OnBanner { get; set; }
    }
}