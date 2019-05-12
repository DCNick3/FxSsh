using System;
using System.Net.Sockets;
using FxSsh;

namespace FxSsh
{
    class Program
    {
        static void Main(string[] args)
        {
            Socket s = new Socket(SocketType.Stream, ProtocolType.Tcp);
            s.Connect("localhost", 2222);
            
            ClientSession session = new ClientSession(s);
        }
    }
}