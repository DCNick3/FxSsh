using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using FxSsh.Services;
using FxSsh.Transport;

namespace FxSsh
{
    /// <summary>
    /// Provides ssh server functionality. Opens the listening socket and accepts connections for you
    /// </summary>
    // TODO: Move all configuration-related methods to another class
    // TODO: Rewrite using async pattern
    public class SshServer : IDisposable
    {
        private readonly object _lock = new object();
        private readonly List<Session> _sessions = new List<Session>();
        private bool _isDisposed;
        private TcpListener _listener;
        private bool _started;

        public SshServer()
            : this(new SshServerConfiguration())
        {
        }

        public SshServer(SshServerConfiguration configuration)
        {
            SshServerConfiguration = configuration.Clone();
        }

        public SshServerConfiguration SshServerConfiguration { get; }

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
        public event EventHandler<Exception> ExceptionRaised;
        public event EventHandler<DetermineAlgorithmsArgs> DetermineAlgorithms;

        public void Start()
        {
            lock (_lock)
            {
                CheckDisposed();
                if (_started)
                    throw new InvalidOperationException("The server is already started.");

                _listener = Equals(SshServerConfiguration.LocalAddress, IPAddress.IPv6Any)
                    ? TcpListener.Create(SshServerConfiguration.Port) // dual stack
                    : new TcpListener(SshServerConfiguration.LocalAddress, SshServerConfiguration.Port);
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
                    var session = new ServerSession(socket, SshServerConfiguration.HostKeys,
                        SshServerConfiguration.Services, SshServerConfiguration.ProgramVersion);
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

                    session.DetermineAlgorithms += (s, e) => DetermineAlgorithms?.Invoke(s, e);
                    try
                    {
                        ConnectionAccepted?.Invoke(this, session);
                        session.EstablishConnection();
                    }
                    catch (SshConnectionException ex)
                    {
                        session.Disconnect(ex.DisconnectReason, ex.Message);
                        ExceptionRaised?.Invoke(this, ex);
                    }
                    catch (Exception ex)
                    {
                        session.Disconnect();
                        ExceptionRaised?.Invoke(this, ex);
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