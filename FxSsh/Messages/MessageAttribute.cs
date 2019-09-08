using System;

namespace FxSsh.Messages
{
    [AttributeUsage(AttributeTargets.Class)]
    public sealed class MessageAttribute : Attribute
    {
        public MessageAttribute(string name, byte number)
        {
            Name = name;
            Number = number;
        }

        // ReSharper disable once UnusedAutoPropertyAccessor.Global
        public string Name { get; }
        public byte Number { get; }
    }
}