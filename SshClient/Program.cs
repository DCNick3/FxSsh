using System;
using System.Net.Sockets;
using FxSsh.Algorithms;
using FxSsh.Services.Userauth;

namespace FxSsh
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            //Console.WriteLine(Convert.ToBase64String(new Ed25519Key().ExportInternalBlob()));

            var key = new Ed25519Key().ImportInternalBlob(
                Convert.FromBase64String("cR8fOzOIAxV2j+vW3upfGFFM+Zh7HIHRA+xYi4Z9xPs="));
            //var key = new RsaKey().ImportInternalBlob(
            //    Convert.FromBase64String("BwIAAACkAABSU0EyAAQAAAEAAQADKjiW5UyIad8ITutLjcdtejF4wPA1dk1JFHesDMEhU9pGUUs+HPTmSn67ar3UvVj/1t/+YK01FzMtgq4GHKzQHHl2+N+onWK4qbIAMgC6vIcs8u3d38f3NFUfX+lMnngeyxzbYITtDeVVXcLnFd7NgaOcouQyGzYrHBPbyEivswsnqcnF4JpUTln29E1mqt0a49GL8kZtDfNrdRSt/opeexhCuzSjLPuwzTPc6fKgMc6q4MBDBk53vrFY2LtGALrpg3tuydh3RbMLcrVyTNT+7st37goubQ2xWGgkLvo+TZqu3yutxr1oLSaPMSmf9bTACMi5QDicB3CaWNe9eU73MzhXaFLpNpBpLfIuhUaZ3COlMazs7H9LCJMXEL95V6ydnATf7tyO0O+jQp7hgYJdRLR3kNAKT0HU8enE9ZbQEXG88hSCbpf1PvFUytb1QBcotDy6bQ6vTtEAZV+XwnUGwFRexERWuu9XD6eVkYjA4Y3PGtSXbsvhwgH0mTlBOuH4soy8MV4dxGkxM8fIMM0NISTYrPvCeyozSq+NDkekXztFau7zdVEYmhCqIjeMNmRGuiEo8ppJYj4CvR1hc8xScUIw7N4OnLISeAdptm97ADxZqWWFZHno7j7rbNsq5ysdx08OtplghFPx4vNHlS09LwdStumtUel5oIEVMYv+yWBYSPPZBcVY5YFyZFJzd0AOkVtUbEbLuzRs5AtKZG01Ip/8+pZQvJvdbBMLT1BUvHTrccuRbY03SHIaUM3cTUc="));
            Console.WriteLine(Convert.ToBase64String(key.ExportKeyAndCertificatesData()));
            Console.WriteLine(key.GetFingerprint("sha256"));

            var s = new Socket(SocketType.Stream, ProtocolType.Tcp);
            s.Connect("localhost", 2222);

            var auth = new ClientAuthParameters
            {
                Username = "dcnick3",
                ServiceName = "ssh-connection",
                Methods = new []
                {
                    new PublicKeyUserauthClientMethod(key), 
                },
                OnBanner = (_, a) => Console.WriteLine(a.Message),
            };

            var session = new ClientSession(s, "SSH-2.0-magic", auth);

            session.Disconnected += (sender, ea) => { Console.WriteLine("Disconnected"); };

            session.EstablishConnection();
        }
    }
}