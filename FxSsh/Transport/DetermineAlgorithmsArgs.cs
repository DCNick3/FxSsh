namespace FxSsh.Transport
{
    public class DetermineAlgorithmsArgs
    {
        public string[] KeyExchangeAlgorithms { get; set; }
        public string[] ServerHostKeyAlgorithms { get; set; }

        public string[] EncryptionAlgorithmsClientToServer { get; set; }
        public string[] EncryptionAlgorithmsServerToClient { get; set; }

        public string[] MacAlgorithmsClientToServer { get; set; }
        public string[] MacAlgorithmsServerToClient { get; set; }
        
        public string[] CompressionAlgorithmsClientToServer { get; set; }
        public string[] CompressionAlgorithmsServerToClient { get; set; }
    }
}