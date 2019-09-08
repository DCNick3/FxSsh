using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using FxSsh.Messages;
using FxSsh.Messages.Connection;
using FxSsh.Services.Userauth.Server;
using FxSsh.Transport;
using FxSsh.Util;

namespace FxSsh.Services
{
    public class ConnectionService : ISshService, IMessageHandler
    {
        private readonly AuthInfo _auth;
        private readonly List<Channel> _channels = new List<Channel>();
        private readonly object _locker = new object();
        protected internal readonly ServerSession session;

        private int _serverChannelCounter = -1;

        public ConnectionService(ServerSession session, AuthInfo auth)
        {
            this.session = session;
            _auth = auth;
        }

        public void CloseService()
        {
            lock (_locker)
            {
                foreach (var channel in _channels.ToArray())
                    channel.ForceClose();
            }
        }

        public void HandleMessageCore(Message message) => this.InvokeHandleMessage((ConnectionServiceMessage) message);

        public event EventHandler<CommandRequestedArgs> CommandOpened;
        public event EventHandler<EnvironmentArgs> EnvReceived;
        public event EventHandler<PtyArgs> PtyReceived;
        public event EventHandler<TcpRequestArgs> TcpForwardRequest;

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(ChannelOpenMessage message)
        {
            switch (message.ChannelType)
            {
                case "session":
                    var msg = Message.LoadFrom<SessionOpenMessage>(message);
                    HandleMessage(msg);
                    break;
                case "direct-tcpip":
                    var tcpMsg = Message.LoadFrom<DirectTcpIpMessage>(message);
                    HandleMessage(tcpMsg);
                    break;
                case "forwarded-tcpip":
                    var forwardMsg = Message.LoadFrom<ForwardedTcpIpMessage>(message);
                    HandleMessage(forwardMsg);
                    break;
                default:
                    session.SendMessage(new ChannelOpenFailureMessage
                    {
                        RecipientChannel = message.SenderChannel,
                        ReasonCode = ChannelOpenFailureReason.UnknownChannelType,
                        Description = $"Unknown channel type: {message.ChannelType}."
                    });
                    throw new SshConnectionException($"Unknown channel type: {message.ChannelType}.");
            }
        }

        // ReSharper disable once UnusedMember.Local
        // ReSharper disable once UnusedParameter.Local
        private void HandleMessage(ShouldIgnoreMessage message)
        {
        }

        private void HandleMessage(ForwardedTcpIpMessage message)
        {
            var channel = HandleChannelOpenMessage(message);
            var args = new TcpRequestArgs(channel,
                message.Address,
                (int) message.Port,
                message.OriginatorIpAddress,
                (int) message.OriginatorPort,
                _auth);
            TcpForwardRequest?.Invoke(this, args);
        }

        private void HandleMessage(DirectTcpIpMessage message)
        {
            var channel = HandleChannelOpenMessage(message);
            var args = new TcpRequestArgs(channel,
                message.Host,
                (int) message.Port,
                message.OriginatorIpAddress,
                (int) message.OriginatorPort,
                _auth);
            TcpForwardRequest?.Invoke(this, args);
        }

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(ChannelRequestMessage message)
        {
            switch (message.RequestType)
            {
                case "exec":
                    var msg = Message.LoadFrom<CommandRequestMessage>(message);
                    HandleMessage(msg);
                    break;
                case "shell":
                    var shellMsg = Message.LoadFrom<ShellRequestMessage>(message);
                    HandleMessage(shellMsg);
                    break;
                case "pty-req":
                    var ptyMsg = Message.LoadFrom<PtyRequestMessage>(message);
                    HandleMessage(ptyMsg);
                    break;
                case "env":
                    var envMsg = Message.LoadFrom<EnvMessage>(message);
                    HandleMessage(envMsg);
                    break;
                case "subsystem":
                    var subMsg = Message.LoadFrom<SubsystemRequestMessage>(message);
                    HandleMessage(subMsg);
                    break;
                case "window-change":
                    break;
                case "simple@putty.projects.tartarus.org":
                    //https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixF.html
                    if (message.WantReply)
                    {
                        var c = FindChannelByServerId<SessionChannel>(message.RecipientChannel);
                        session.SendMessage(new ChannelSuccessMessage {RecipientChannel = c.ClientChannelId});
                    }

                    break;
                case "winadj@putty.projects.tartarus.org":
                    //https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixF.html
                    var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);
                    session.SendMessage(new ChannelFailureMessage {RecipientChannel = channel.ClientChannelId});
                    break;
                default:
                    if (message.WantReply)
                        session.SendMessage(new ChannelFailureMessage
                        {
                            RecipientChannel = FindChannelByServerId<Channel>(message.RecipientChannel).ClientChannelId
                        });
                    throw new SshConnectionException($"Unknown request type: {message.RequestType}.");
            }
        }

        private void HandleMessage(EnvMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            EnvReceived?.Invoke(this, new EnvironmentArgs(channel, message.Name, message.Value, _auth));

            if (message.WantReply)
                session.SendMessage(new ChannelSuccessMessage {RecipientChannel = channel.ClientChannelId});
        }

        private void HandleMessage(PtyRequestMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            PtyReceived?.Invoke(this,
                new PtyArgs(channel,
                    message.Terminal,
                    message.heightPx,
                    message.heightRows,
                    message.widthPx,
                    message.widthChars,
                    message.modes, _auth));

            if (message.WantReply)
                session.SendMessage(new ChannelSuccessMessage {RecipientChannel = channel.ClientChannelId});
        }

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(ChannelDataMessage message)
        {
            var channel = FindChannelByServerId<Channel>(message.RecipientChannel);
            channel.OnData(message.Data);
        }

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(ChannelWindowAdjustMessage message)
        {
            var channel = FindChannelByServerId<Channel>(message.RecipientChannel);
            channel.ClientAdjustWindow(message.BytesToAdd);
        }

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(ChannelEofMessage message)
        {
            var channel = FindChannelByServerId<Channel>(message.RecipientChannel);
            channel.OnEof();
        }

        // ReSharper disable once UnusedMember.Local
        private void HandleMessage(ChannelCloseMessage message)
        {
            var channel = FindChannelByServerId<Channel>(message.RecipientChannel);
            channel.OnClose();
        }

        private void HandleMessage(SessionOpenMessage message)
        {
            HandleChannelOpenMessage(message);
        }

        private SessionChannel HandleChannelOpenMessage(ChannelOpenMessage message)
        {
            var channel = new SessionChannel(
                this,
                message.SenderChannel,
                message.InitialWindowSize,
                message.MaximumPacketSize,
                (uint) Interlocked.Increment(ref _serverChannelCounter));

            lock (_locker)
            {
                _channels.Add(channel);
            }

            var msg = new ChannelOpenConfirmationMessage
            {
                RecipientChannel = channel.ClientChannelId,
                SenderChannel = channel.ServerChannelId,
                InitialWindowSize = channel.ServerInitialWindowSize,
                MaximumPacketSize = channel.ServerMaxPacketSize
            };

            session.SendMessage(msg);
            return channel;
        }

        private void HandleMessage(ShellRequestMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            if (message.WantReply)
                session.SendMessage(new ChannelSuccessMessage {RecipientChannel = channel.ClientChannelId});

            CommandOpened?.Invoke(this, new CommandRequestedArgs(channel, "shell", null, _auth));
        }

        private void HandleMessage(CommandRequestMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            if (message.WantReply)
                session.SendMessage(new ChannelSuccessMessage {RecipientChannel = channel.ClientChannelId});

            CommandOpened?.Invoke(this, new CommandRequestedArgs(channel, "exec", message.Command, _auth));
        }

        private void HandleMessage(SubsystemRequestMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            if (message.WantReply)
                session.SendMessage(new ChannelSuccessMessage {RecipientChannel = channel.ClientChannelId});

            CommandOpened?.Invoke(this, new CommandRequestedArgs(channel, "subsystem", message.Name, _auth));
        }

        private T FindChannelByServerId<T>(uint id) where T : Channel
        {
            lock (_locker)
            {
                var channel = _channels.FirstOrDefault(x => x.ServerChannelId == id) as T;
                if (channel == null)
                    throw new SshConnectionException($"Invalid server channel id {id}.",
                        DisconnectReason.ProtocolError);

                return channel;
            }
        }

        internal void RemoveChannel(Channel channel)
        {
            lock (_locker)
            {
                _channels.Remove(channel);
            }
        }
    }
}