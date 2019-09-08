using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Algorithms;
using FxSsh.Services;
using FxSsh.Services.Userauth.Server;
using FxSsh.Transport;
using MiniTerm;

namespace SshServerLoader
{
    internal class Program
    {
        private static int _windowWidth, _windowHeight;

        private static void Main(string[] args)
        {
            var config = new SshServerConfiguration(IPAddress.Loopback, 2222, "SSH-2.0-FxSsh")
            //server.AddHostKey("ssh-rsa", "BwIAAACkAABSU0EyAAQAAAEAAQADKjiW5UyIad8ITutLjcdtejF4wPA1dk1JFHesDMEhU9pGUUs+HPTmSn67ar3UvVj/1t/+YK01FzMtgq4GHKzQHHl2+N+onWK4qbIAMgC6vIcs8u3d38f3NFUfX+lMnngeyxzbYITtDeVVXcLnFd7NgaOcouQyGzYrHBPbyEivswsnqcnF4JpUTln29E1mqt0a49GL8kZtDfNrdRSt/opeexhCuzSjLPuwzTPc6fKgMc6q4MBDBk53vrFY2LtGALrpg3tuydh3RbMLcrVyTNT+7st37goubQ2xWGgkLvo+TZqu3yutxr1oLSaPMSmf9bTACMi5QDicB3CaWNe9eU73MzhXaFLpNpBpLfIuhUaZ3COlMazs7H9LCJMXEL95V6ydnATf7tyO0O+jQp7hgYJdRLR3kNAKT0HU8enE9ZbQEXG88hSCbpf1PvFUytb1QBcotDy6bQ6vTtEAZV+XwnUGwFRexERWuu9XD6eVkYjA4Y3PGtSXbsvhwgH0mTlBOuH4soy8MV4dxGkxM8fIMM0NISTYrPvCeyozSq+NDkekXztFau7zdVEYmhCqIjeMNmRGuiEo8ppJYj4CvR1hc8xScUIw7N4OnLISeAdptm97ADxZqWWFZHno7j7rbNsq5ysdx08OtplghFPx4vNHlS09LwdStumtUel5oIEVMYv+yWBYSPPZBcVY5YFyZFJzd0AOkVtUbEbLuzRs5AtKZG01Ip/8+pZQvJvdbBMLT1BUvHTrccuRbY03SHIaUM3cTUc=");
            //server.AddHostKey("ssh-dss", "BwIAAAAiAABEU1MyAAQAAG+6KQWB+crih2Ivb6CZsMe/7NHLimiTl0ap97KyBoBOs1amqXB8IRwI2h9A10R/v0BHmdyjwe0c0lPsegqDuBUfD2VmsDgrZ/i78t7EJ6Sb6m2lVQfTT0w7FYgVk3J1Deygh7UcbIbDoQ+refeRNM7CjSKtdR+/zIwO3Qub2qH+p6iol2iAlh0LP+cw+XlH0LW5YKPqOXOLgMIiO+48HZjvV67pn5LDubxru3ZQLvjOcDY0pqi5g7AJ3wkLq5dezzDOOun72E42uUHTXOzo+Ct6OZXFP53ZzOfjNw0SiL66353c9igBiRMTGn2gZ+au0jMeIaSsQNjQmWD+Lnri39n0gSCXurDaPkec+uaufGSG9tWgGnBdJhUDqwab8P/Ipvo5lS5p6PlzAQAAACqx1Nid0Ea0YAuYPhg+YolsJ/ce");
            .UseHostKey("ssh-ed25519", "GQ6qKeU8/fQ6r2FGrUkDU1aAlavjD90MooErxtCwgDo=")
            
            // TODO: split the SshServer and SshServerBuilder
            .UseUserauthService(new IServerMethodFactory[]
            {
                new CallbackPublicKeyServerMethodFactory(CheckPublicKey), 
                new CallbackPasswordServerMethodFactory(CheckPassword), 
                new CallbackHostbasedServerMethodFactory(CheckHostbased), 
            });
            
            var server = new SshServer(config);
            
            server.DetermineAlgorithms += (s, e) =>
            {
                // This looks ugly. User should have more convenient way to do this
                e.EncryptionAlgorithmsClientToServer = e.EncryptionAlgorithmsClientToServer
                    .Where(_ => !_.StartsWith("aes128") && !_.StartsWith("3des")).ToArray();
                e.EncryptionAlgorithmsServerToClient = e.EncryptionAlgorithmsServerToClient
                    .Where(_ => !_.StartsWith("aes128") && !_.StartsWith("3des")).ToArray();

                e.MacAlgorithmsClientToServer = e.MacAlgorithmsClientToServer.Where(_ => _ != "hmac-md5").ToArray();
                e.MacAlgorithmsServerToClient = e.MacAlgorithmsServerToClient.Where(_ => _ != "hmac-md5").ToArray();

                // non-same encryption works!
                e.EncryptionAlgorithmsClientToServer =
                    e.EncryptionAlgorithmsClientToServer.Where(_ => _ != "aes192-ctr").ToArray();
            };

            server.ConnectionAccepted += server_ConnectionAccepted;

            server.Start();

            Task.Delay(-1).Wait();
        }


        private static void server_ConnectionAccepted(object sender, ServerSession e)
        {
            Console.WriteLine("Accepted a client.");

            e.ServiceRegistered += e_ServiceRegistered;
            e.AlgorithmsDetermined += EAlgorithmsDetermined;
        }

        private static void EAlgorithmsDetermined(object sender, AlgorithmsDeterminedArgs e)
        {
            /*foreach (var keyExchangeAlg in e.KeyExchangeAlgorithms)
                Console.WriteLine("Key exchange algorithm: {0}", keyExchangeAlg);*/
        }

        private static void e_ServiceRegistered(object sender, ISshService e)
        {
            var session = (Session) sender;
            Console.WriteLine("Session {0} requesting {1}.",
                BitConverter.ToString(session.SessionId).Replace("-", ""), e.GetType().Name);

            if (e is UserauthServerService userauthServerService)
            {
                //userauthServerService.CheckAuthData += ServiceCheckAuthData;
            }
            else if (e is ConnectionService)
            {
                var service = (ConnectionService) e;
                service.CommandOpened += service_CommandOpened;
                service.EnvReceived += service_EnvReceived;
                service.PtyReceived += service_PtyReceived;
                service.TcpForwardRequest += service_TcpForwardRequest;
            }
        }

        private static void service_TcpForwardRequest(object sender, TcpRequestArgs e)
        {
            Console.WriteLine("Received a request to forward data to {0}:{1}", e.Host, e.Port);

            var allow = true; // func(e.Host, e.Port, e.AttachedUserauthArgs);

            if (!allow)
                return;

            var tcp = new TcpForwardService(e.Host, e.Port, e.OriginatorIp, e.OriginatorPort);
            e.Channel.DataReceived += (ss, ee) => tcp.OnData(ee);
            e.Channel.CloseReceived += (ss, ee) => tcp.OnClose();
            tcp.DataReceived += (ss, ee) => e.Channel.SendData(ee);
            tcp.CloseReceived += (ss, ee) => e.Channel.SendClose();
            tcp.Start();
        }

        private static void service_PtyReceived(object sender, PtyArgs e)
        {
            Console.WriteLine("Request to create a PTY received for terminal type {0}", e.Terminal);
            _windowWidth = (int) e.WidthChars;
            _windowHeight = (int) e.HeightRows;
        }

        private static void service_EnvReceived(object sender, EnvironmentArgs e)
        {
            Console.WriteLine("Received environment variable {0}:{1}", e.Name, e.Value);
        }

        private static bool CheckPublicKey((ServerSession session, string username, string serviceName, PublicKeyAlgorithm key) args)
        {
            var (session, username, serviceName, key) = args;
            
            Console.WriteLine($"User {username} with key {key.GetFingerprint()} wants {serviceName}");
            
            return false;

            //Console.WriteLine("Client {0} fingerprint: {1}.", e.KeyAlgorithm, e.Fingerprint);

            //e.Result = true;
        }
        private static bool CheckPassword((ServerSession session, string username, string serviceName, string password) args)
        {
            var (session, username, serviceName, password) = args;

            Console.WriteLine($"User {username} with password {password} wants {serviceName}");
            
            return true;
        }
        private static bool CheckHostbased((ServerSession sesion, string username, string serviceName, string hostname, string hostUsername, PublicKeyAlgorithm key) arg)
        {
            var (session, username, serviceName, hostname, hostUsername, key) = arg;
            
            Console.WriteLine(
                $"User ${username} from ${hostUsername}@${hostname} wih key ${key.GetFingerprint()} wants ${serviceName}");

            return true;
        }

        private static void service_CommandOpened(object sender, CommandRequestedArgs e)
        {
            Console.WriteLine($"Channel {e.Channel.ServerChannelId} runs {e.ShellType}: \"{e.CommandText}\".");

            var allow = true; // func(e.ShellType, e.CommandText, e.AttachedUserauthArgs);

            if (!allow)
                return;

            if (e.ShellType == "shell")
            {
                // requirements: Windows 10 RedStone 5, 1809
                // also, you can call powershell.exe
                var terminal = new Terminal("cmd.exe", _windowWidth, _windowHeight);

                e.Channel.DataReceived += (ss, ee) => terminal.OnInput(ee);
                e.Channel.CloseReceived += (ss, ee) => terminal.OnClose();
                terminal.DataReceived += (ss, ee) => e.Channel.SendData(ee);
                terminal.CloseReceived += (ss, ee) => e.Channel.SendClose(ee);

                terminal.Run();
            }
            else if (e.ShellType == "exec")
            {
                /*
                var parser = new Regex(@"(?<cmd>git-receive-pack|git-upload-pack|git-upload-archive) \'/?(?<proj>.+)\.git\'");
                var match = parser.Match(e.CommandText);
                var command = match.Groups["cmd"].Value;
                var project = match.Groups["proj"].Value;

                var git = new GitService(command, project);

                e.Channel.DataReceived += (ss, ee) => git.OnData(ee);
                e.Channel.CloseReceived += (ss, ee) => git.OnClose();
                git.DataReceived += (ss, ee) => e.Channel.SendData(ee);
                git.CloseReceived += (ss, ee) => e.Channel.SendClose(ee);

                git.Start();
                */

                e.Channel.SendData(Encoding.UTF8.GetBytes($"you entered: {e.CommandText}\n"));
                e.Channel.SendEof();
                e.Channel.SendClose(0);
            }
            else if (e.ShellType == "subsystem")
            {
                // do something more
            }
        }
    }
}