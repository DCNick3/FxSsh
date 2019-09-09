using System;
using System.Threading;
using FxSsh.Messages.Connection;
using FxSsh.Transport;

namespace FxSsh.Services.Connection
{
    public abstract class Channel
    {
        protected readonly ConnectionService connectionService;
        protected readonly EventWaitHandle sendingWindowWaitHandle = new ManualResetEvent(false);

        public Channel(ConnectionService connectionService,
            uint clientChannelId, uint clientInitialWindowSize, uint clientMaxPacketSize,
            uint serverChannelId)
        {
            this.connectionService = connectionService;

            ClientChannelId = clientChannelId;
            ClientInitialWindowSize = clientInitialWindowSize;
            ClientWindowSize = clientInitialWindowSize;
            ClientMaxPacketSize = clientMaxPacketSize;

            ServerChannelId = serverChannelId;
            ServerInitialWindowSize = Session.InitialLocalWindowSize;
            ServerWindowSize = Session.InitialLocalWindowSize;
            ServerMaxPacketSize = Session.LocalChannelDataPacketSize;
        }

        public uint ClientChannelId { get; }
        public uint ClientInitialWindowSize { get; }
        public uint ClientWindowSize { get; protected set; }
        public uint ClientMaxPacketSize { get; }

        public uint ServerChannelId { get; }
        public uint ServerInitialWindowSize { get; }
        public uint ServerWindowSize { get; protected set; }
        public uint ServerMaxPacketSize { get; }

        public bool ClientClosed { get; private set; }
        public bool ClientMarkedEof { get; private set; }
        public bool ServerClosed { get; private set; }
        public bool ServerMarkedEof { get; private set; }

        public event EventHandler<byte[]> DataReceived;
        public event EventHandler EofReceived;
        public event EventHandler CloseReceived;

        public void SendData(byte[] data)
        {
            if (data.Length == 0) return;

            var msg = new ChannelDataMessage();
            msg.RecipientChannel = ClientChannelId;

            var total = (uint) data.Length;
            var offset = 0L;
            byte[] buf = null;
            do
            {
                var packetSize = Math.Min(Math.Min(ClientWindowSize, ClientMaxPacketSize), total);
                if (packetSize == 0)
                {
                    sendingWindowWaitHandle.WaitOne();
                    continue;
                }

                if (buf == null || packetSize != buf.Length)
                    buf = new byte[packetSize];
                Array.Copy(data, offset, buf, 0, packetSize);

                msg.Data = buf;
                connectionService.session.SendMessage(msg);

                ClientWindowSize -= packetSize;
                total -= packetSize;
                offset += packetSize;
            } while (total > 0);
        }

        public void SendEof()
        {
            if (ServerMarkedEof)
                return;

            ServerMarkedEof = true;
            var msg = new ChannelEofMessage {RecipientChannel = ClientChannelId};
            connectionService.session.SendMessage(msg);
        }

        public void SendClose(uint? exitCode = null)
        {
            if (ServerClosed)
                return;

            ServerClosed = true;
            if (exitCode.HasValue)
                connectionService.session.SendMessage(new ExitStatusMessage
                    {RecipientChannel = ClientChannelId, ExitStatus = exitCode.Value});
            connectionService.session.SendMessage(new ChannelCloseMessage {RecipientChannel = ClientChannelId});

            CheckBothClosed();
        }

        internal void OnData(byte[] data)
        {
            ServerAttemptAdjustWindow((uint) data.Length);

            if (DataReceived != null)
                DataReceived(this, data);
        }

        internal void OnEof()
        {
            ClientMarkedEof = true;

            EofReceived?.Invoke(this, EventArgs.Empty);
        }

        internal void OnClose()
        {
            ClientClosed = true;

            CloseReceived?.Invoke(this, EventArgs.Empty);

            CheckBothClosed();
        }

        internal void ClientAdjustWindow(uint bytesToAdd)
        {
            ClientWindowSize += bytesToAdd;

            // pulse multithreadings in same time and unsignal until thread switched
            // don't try to use AutoResetEvent
            // TODO: WTF
            sendingWindowWaitHandle.Set();
            Thread.Sleep(1);
            sendingWindowWaitHandle.Reset();
        }

        private void ServerAttemptAdjustWindow(uint messageLength)
        {
            ServerWindowSize -= messageLength;
            if (ServerWindowSize <= ServerMaxPacketSize)
            {
                connectionService.session.SendMessage(new ChannelWindowAdjustMessage
                {
                    RecipientChannel = ClientChannelId,
                    BytesToAdd = ServerInitialWindowSize - ServerWindowSize
                });
                ServerWindowSize = ServerInitialWindowSize;
            }
        }

        private void CheckBothClosed()
        {
            if (ClientClosed && ServerClosed) ForceClose();
        }

        internal void ForceClose()
        {
            connectionService.RemoveChannel(this);
            sendingWindowWaitHandle.Set();
            sendingWindowWaitHandle.Close();
        }
    }
}