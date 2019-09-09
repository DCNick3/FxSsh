using System;
using System.Diagnostics.CodeAnalysis;

namespace FxSsh.Transport
{
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class AlgorithmsDeterminedArgs : EventArgs
    {
        public string KeyExchange { get; set; }

        public string PublicKey { get; set; }
        public string ReceiveCompression { get; set; }
        public string ReceiveEncryption { get; set; }
        public string ReceiveHmac { get; set; }

        public string TransmitCompression { get; set; }
        public string TransmitEncryption { get; set; }
        public string TransmitHmac { get; set; }
    }
}