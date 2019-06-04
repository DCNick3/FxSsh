using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using FxSsh.Services;
using FxSsh.Services.Userauth;

namespace FxSsh
{
    public class SshServer : IDisposable
    {
        private readonly Dictionary<string, byte[]> _hostKey = new Dictionary<string, byte[]>();
        private readonly Dictionary<string, ISshServerServiceFactory> _serviceFactories =
            new Dictionary<string, ISshServerServiceFactory>();
        private readonly object _lock = new object();
        private readonly List<Session> _sessions = new List<Session>();
        private bool _isDisposed;
        private TcpListener _listener;
        private bool _started;

        public SshServer()
            : this(new StartingInfo())
        {
        }

        public SshServer(StartingInfo info)
        {
            Contract.Requires(info != null);

            StartingInfo = info;
        }

        public StartingInfo StartingInfo { get; }

        #region IDisposable

        public void Dispose()
        {
            lock (_lock)
            {
                if (_isDisposed)
                    return;
                Stop();
            }
        }

        #endregion

        public event EventHandler<ServerSession> ConnectionAccepted;
        public event EventHandler<Exception> ExceptionRasied;
        public event EventHandler<PreKeyExchangeArgs> PreKeyExchange;

        public void Start()
        {
            lock (_lock)
            {
                CheckDisposed();
                if (_started)
                    throw new InvalidOperationException("The server is already started.");

                _listener = Equals(StartingInfo.LocalAddress, IPAddress.IPv6Any)
                    ? TcpListener.Create(StartingInfo.Port) // dual stack
                    : new TcpListener(StartingInfo.LocalAddress, StartingInfo.Port);
                _listener.ExclusiveAddressUse = false;
                _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                _listener.Start();
                BeginAcceptSocket();

                _started = true;
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                CheckDisposed();
                if (!_started)
                    throw new InvalidOperationException("The server is not started.");

                _listener.Stop();

                _isDisposed = true;
                _started = false;

                foreach (var session in _sessions.ToArray())
                    try
                    {
                        session.Disconnect();
                    }
                    catch
                    {
                        // ignored
                    }
            }
        }

        public void AddHostKey(string type, string xml)
        {
            Contract.Requires(type != null);
            Contract.Requires(xml != null);

            AddHostKey(type, Convert.FromBase64String(xml));
        }

        public void AddHostKey(string type, byte[] key)
        {
            Contract.Requires(type != null);
            Contract.Requires(key != null);

            if (!_hostKey.ContainsKey(type))
                _hostKey.Add(type, key.ToArray());
        }

        public void AddServiceFactory(ISshServerServiceFactory factory)
        {
            _serviceFactories.Add(factory.GetServiceName(), factory);
        }

        public void AddUserauthService(IReadOnlyList<IServerMethodFactory> methods)
        {
            AddUserauthService(methods, new AnyServerAuthenticator());
        }
        
        public void AddUserauthService(IReadOnlyList<IServerMethodFactory> methods, IServerAuthenticator authenticator)
        {
            AddServiceFactory(new UserauthServerServiceFactory(methods, authenticator));
        }
        
        private void BeginAcceptSocket()
        {
            try
            {
                _listener.BeginAcceptSocket(AcceptSocket, null);
            }
            catch (ObjectDisposedException)
            {
            }
            catch
            {
                if (_started)
                    BeginAcceptSocket();
            }
        }

        private void AcceptSocket(IAsyncResult ar)
        {
            try
            {
                var socket = _listener.EndAcceptSocket(ar);
                Task.Run(() =>
                {
                    var session = new ServerSession(socket, _hostKey, _serviceFactories, StartingInfo.ServerBanner);
                    session.Disconnected += (ss, ee) =>
                    {
                        lock (_lock)
                        {
                            _sessions.Remove(session);
                        }
                    };
                    lock (_lock)
                    {
                        _sessions.Add(session);
                    }

                    session.PreKeyExchange += (s, e) => PreKeyExchange?.Invoke(s, e);
                    try
                    {
                        ConnectionAccepted?.Invoke(this, session);
                        session.EstablishConnection();
                    }
                    catch (SshConnectionException ex)
                    {
                        session.Disconnect(ex.DisconnectReason, ex.Message);
                        ExceptionRasied?.Invoke(this, ex);
                    }
                    catch (Exception ex)
                    {
                        session.Disconnect();
                        ExceptionRasied?.Invoke(this, ex);
                    }
                });
            }
            catch
            {
                // ignored
            }
            finally
            {
                BeginAcceptSocket();
            }
        }

        private void CheckDisposed()
        {
            if (_isDisposed)
                throw new ObjectDisposedException(GetType().FullName);
        }
    }
}