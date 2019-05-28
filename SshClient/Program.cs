using System.Net.Sockets;

namespace FxSsh
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var s = new Socket(SocketType.Stream, ProtocolType.Tcp);
            s.Connect("localhost", 2222);

            var session = new ClientSession(s, "SSH-2.0-magic");

            session.EstablishConnection();
        }
    }
}