using System;
using System.Net.Sockets;
using FxSsh.Algorithms;
using FxSsh.Services;

namespace FxSsh
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            //Console.WriteLine(Convert.ToBase64String(new Ed25519Key().ExportInternalBlob()));

            var s = new Socket(SocketType.Stream, ProtocolType.Tcp);
            s.Connect("localhost", 2222);


            var auth = new ClientAuthParameters
            {
                Username = "dcnick3",
                HostAuth = null,
                OnBanner = (_, a) => Console.WriteLine(a.Message),
                PasswordAuthHandler = null,
                ServiceName = "ssh-connection",
                UserKeys = new[]
                {
                    new DssKey(), new RsaKey(),
                    new Ed25519Key().ImportInternalBlob(
                        Convert.FromBase64String("cR8fOzOIAxV2j+vW3upfGFFM+Zh7HIHRA+xYi4Z9xPs="))
                }
            };

            var session = new ClientSession(s, "SSH-2.0-magic", auth);

            session.Disconnected += (sender, ea) => { Console.WriteLine("Disconnected"); };

            session.EstablishConnection();
        }
    }
}