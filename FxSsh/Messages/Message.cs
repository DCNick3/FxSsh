using System;
using FxSsh.Messages.Userauth;
using FxSsh.Util;

namespace FxSsh.Messages
{
    public abstract class Message
    {
        public enum Group
        {
            TransportLayerGeneric,
            AlgorithmNegotiations,
            KeyExchangeMethodSpecific,
            UserauthGeneric,
            UserauthMethodSpecific,
            ConnectionProtocolGeneric,
            ChannelRelated,
            Reserved,
            LocalExtensions
        }

        public abstract byte MessageType { get; }
        public Group MessageGroup => GetGroup(MessageType);
        
        protected byte[] RawBytes { get; set; }

        public void LoadPacket(byte[] bytes)
        {
            RawBytes = bytes;
            using (var worker = new SshDataWorker(bytes))
            {
                var number = worker.ReadByte();
                if (number != MessageType)
                    throw new ArgumentException($"Message type {number} is not valid.");

                LoadPacketInternal(worker);
            }
        }

        public byte[] SerializePacket()
        {
            using (var worker = new SshDataWorker())
            {
                worker.Write(MessageType);

                SerializePacketInternal(worker);

                return worker.ToByteArray();
            }
        }

        public static T LoadFrom<T>(Message message) where T : Message, new()
        {
            var msg = new T();
            msg.LoadPacket(message.RawBytes);
            return msg;
        }

        public static Message LoadFrom(RequestMessage message, Type type)
        {
            var msg = (Message)Activator.CreateInstance(type);
            msg.LoadPacket(message.RawBytes);
            return msg;
        }

        protected virtual void LoadPacketInternal(SshDataWorker reader) => throw new NotSupportedException();

        protected virtual void SerializePacketInternal(SshDataWorker writer) => throw new NotSupportedException();

        public static Group GetGroup(byte number)
        {
            switch (number)
            {
                case var n when n >= 1 && n <= 19:
                    return Group.TransportLayerGeneric;
                case var n when n >= 20 && n <= 29:
                    return Group.AlgorithmNegotiations;
                case var n when n >= 30 && n <= 49:
                    return Group.KeyExchangeMethodSpecific;
                case var n when n >= 50 && n <= 59:
                    return Group.UserauthGeneric;
                case var n when n >= 60 && n <= 79:
                    return Group.UserauthMethodSpecific;
                case var n when n >= 80 && n <= 89:
                    return Group.ConnectionProtocolGeneric;
                case var n when n >= 90 && n <= 127:
                    return Group.ChannelRelated;
                case var n when n >= 128 && n <= 191:
                    return Group.Reserved;
                case var n when n >= 192 && n <= 255:
                    return Group.LocalExtensions;
                default:
                    throw new ArgumentOutOfRangeException(nameof(number));
            }
        }
    }
}