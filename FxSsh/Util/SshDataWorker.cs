﻿using System;
using System.IO;
using System.Text;

namespace FxSsh.Util
{
    /// <summary>
    /// Swiss army knife for serializing and deserializing data, as specified by ssh transport RFC 
    /// </summary>
    public class SshDataWorker : IDisposable
    {
        private readonly MemoryStream _ms;

        public SshDataWorker() => _ms = new MemoryStream(512);

        public SshDataWorker(byte[] buffer) => _ms = new MemoryStream(buffer);
        
        public long DataAvailable => _ms.Length - _ms.Position;

        public void Dispose() => _ms.Dispose();

        public void Write(bool value) => _ms.WriteByte(value ? (byte) 1 : (byte) 0);

        public void Write(byte value) => _ms.WriteByte(value);

        public void Write(uint value)
        {
            var bytes = new[] {(byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) (value & 0xFF)};
            _ms.Write(bytes, 0, 4);
        }

        public void Write(ulong value)
        {
            var bytes = new[]
            {
                (byte) (value >> 56), (byte) (value >> 48), (byte) (value >> 40), (byte) (value >> 32),
                (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) (value & 0xFF)
            };
            _ms.Write(bytes, 0, 8);
        }

        public void Write(string str, Encoding encoding)
        {
            var bytes = encoding.GetBytes(str);
            Write(bytes);
        }

        public void WriteMpint(byte[] data)
        {
            if (data.Length == 1 && data[0] == 0)
            {
                WriteRawBytes(new byte[4]);
            }
            else
            {
                var length = (uint) data.Length;
                var high = (data[0] & 0x80) != 0;
                if (high)
                {
                    Write(length + 1);
                    Write(0);
                    WriteRawBytes(data);
                }
                else
                {
                    Write(length);
                    WriteRawBytes(data);
                }
            }
        }

        /// <summary>
        /// Writes data as-is without any wrapping
        /// </summary>
        public void WriteRawBytes(byte[] data) => _ms.Write(data, 0, data.Length);

        public void Write(byte[] buffer)
        {
            Write((uint) buffer.Length);
            _ms.Write(buffer, 0, buffer.Length);
        }

        public void Write(byte[] buffer, int offset, int count)
        {
            Write((uint) count);
            _ms.Write(buffer, offset, count);
        }

        public bool ReadBoolean()
        {
            var num = _ms.ReadByte();

            if (num == -1)
                throw new EndOfStreamException();
            return num != 0;
        }

        public byte ReadByte()
        {
            var data = ReadBinary(1);
            return data[0];
        }

        public uint ReadUInt32()
        {
            var data = ReadBinary(4);
            return (uint) ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
        }

        public ulong ReadUInt64()
        {
            var data = ReadBinary(8);
            return ((ulong) data[0] << 56) | ((ulong) data[1] << 48) | ((ulong) data[2] << 40) |
                   ((ulong) data[3] << 32) |
                   ((ulong) data[4] << 24) | ((ulong) data[5] << 16) | ((ulong) data[6] << 8) | data[7];
        }

        public string ReadString(Encoding encoding)
        {
            var bytes = ReadBinary();
            return encoding.GetString(bytes);
        }

        public byte[] ReadMpint()
        {
            var data = ReadBinary();

            if (data.Length == 0)
                return new byte[1];

            if (data[0] == 0)
            {
                var output = new byte[data.Length - 1];
                Array.Copy(data, 1, output, 0, output.Length);
                return output;
            }

            return data;
        }

        public byte[] ReadBinary(int length)
        {
            var data = new byte[length];
            var bytesRead = _ms.Read(data, 0, length);

            if (bytesRead < length)
                throw new ArgumentOutOfRangeException("length");

            return data;
        }

        public byte[] ReadBinary()
        {
            var length = ReadUInt32();
            return ReadBinary((int) length);
        }

        public byte[] ToByteArray()
        {
            return _ms.ToArray();
        }
    }
}