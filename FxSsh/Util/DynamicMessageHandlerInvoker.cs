using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq.Expressions;
using System.Reflection;
using FxSsh.Messages;

namespace FxSsh.Util
{
    /// <summary>
    /// Helper class for invoking message handlers
    /// Message handler should be a member accepting one argument - message
    /// </summary>
    public static class DynamicMessageHandlerInvoker
    {
        private static readonly Dictionary<string, Action<IMessageHandler, Message>> Cache =
            new Dictionary<string, Action<IMessageHandler, Message>>();

        public static void InvokeHandleMessage(this IMessageHandler instance, Message message)
        {
            var instanceType = instance.GetType();
            var messageType = message.GetType();

            var key = instanceType.Name + '!' + messageType.Name;
            var action = Cache.ContainsKey(key) ? Cache[key] : null;
            if (action == null)
            {
                var method = instance.GetType()
                    .GetMethod("HandleMessage",
                        BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.FlattenHierarchy,
                        null,
                        new[] {message.GetType()},
                        null);
                
                Debug.Assert(method != null, nameof(method) + " != null");
                
                var instanceParameter = Expression.Parameter(typeof(IMessageHandler));
                var messageParameter = Expression.Parameter(typeof(Message));
                var call = Expression.Call(
                    Expression.Convert(instanceParameter, instanceType),
                    method, 
                    Expression.Convert(messageParameter, messageType));
                action = Expression.Lambda<Action<IMessageHandler, Message>>(call, instanceParameter, messageParameter).Compile();
                Cache[key] = action;
            }

            action(instance, message);
        }
    }

    /// <summary>
    /// Meta interface.
    /// When implemented shows, that class has message handlers,
    ///     that can be invoked with DynamicMessageHandlerInvoker.
    /// </summary>
    public interface IMessageHandler
    {
    }
}