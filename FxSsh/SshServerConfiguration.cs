using System;
using System.Collections.Generic;
using System.Net;
using FxSsh.Algorithms;
using FxSsh.Services;
using FxSsh.Services.Userauth.Server;
using FxSsh.Transport;

namespace FxSsh
{
    public class SshServerConfiguration
    {
        public const int DefaultPort = 2222;

        private Dictionary<string, PublicKeyAlgorithm> _hostKeys = 
            new Dictionary<string, PublicKeyAlgorithm>();
        private Dictionary<string, ISshServerServiceFactory> _serviceFactories =
            new Dictionary<string, ISshServerServiceFactory>();
        
        public SshServerConfiguration()
            : this(IPAddress.IPv6Any, DefaultPort, "SSH-2.0-FxSsh")
        { }

        public SshServerConfiguration(IPAddress localAddress, int port, string programVersion)
        {
            LocalAddress = localAddress;
            Port = port;
            ProgramVersion = programVersion;
        }

        public IPAddress LocalAddress { get; private set; }
        public int Port { get; private set; }
        public string ProgramVersion { get; private set; }
        public IReadOnlyDictionary<string, PublicKeyAlgorithm> HostKeys => _hostKeys;
        public IReadOnlyDictionary<string, ISshServerServiceFactory> Services => _serviceFactories;

        public SshServerConfiguration Clone()
        {
            return new SshServerConfiguration
            {
                LocalAddress = LocalAddress,
                Port = Port,
                ProgramVersion = ProgramVersion,
                _hostKeys = new Dictionary<string, PublicKeyAlgorithm>(_hostKeys),
                _serviceFactories = new Dictionary<string, ISshServerServiceFactory>(_serviceFactories)
            };
        }

        public SshServerConfiguration UseHostKey(string type, string base64Key)
        {
            UseHostKey(type, Convert.FromBase64String(base64Key));
            return this;
        }
        public SshServerConfiguration UseHostKey(string type, byte[] key)
        {
            var algorithm = CryptoAlgorithms.PublicKeyAlgorithms[type];
            return UseHostKey(algorithm.CreateFromInternalBlob(key));
        }
        public SshServerConfiguration UseHostKey(PublicKeyAlgorithm key)
        {
            _hostKeys.Add(key.Name, key);
            return this;
        }
        
        public SshServerConfiguration UseServiceFactory(ISshServerServiceFactory factory)
        {
            _serviceFactories.Add(factory.GetServiceName(), factory);
            return this;
        }
        public SshServerConfiguration UseUserauthService(IReadOnlyList<IServerMethodFactory> methods)
        {
            return UseUserauthService(methods, new AnyServerAuthenticator());
        }
        public SshServerConfiguration UseUserauthService(IReadOnlyList<IServerMethodFactory> methods, IServerAuthenticator authenticator)
        {
            return UseServiceFactory(new UserauthServerServiceFactory(methods, authenticator));
        }
        
        public SshServerConfiguration UseBindAddress(IPAddress localAddress)
        {
            LocalAddress = localAddress;
            return this;
        }
        public SshServerConfiguration UseBindAddress(IPEndPoint endPoint)
        {
            LocalAddress = endPoint.Address;
            Port = endPoint.Port;
            return this;
        }
        public SshServerConfiguration UseProgramVersion(string programVersion)
        {
            ProgramVersion = programVersion;
            return this;
        }
    }
}