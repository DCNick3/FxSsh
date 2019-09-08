using System;
using System.Text;

namespace FxSsh.Services.Userauth.Client
{
    public sealed class InteractivePasswordAuthHandler : IPasswordAuthHandler
    {
        private readonly bool _enableChange;
        
        public InteractivePasswordAuthHandler(bool enableChange = true)
        {
            _enableChange = enableChange;
        }
        
        private string ReadPassword()
        {
            var sb = new StringBuilder();
            while (true)
            {
                var k = Console.ReadKey(true);
                if (k.Key == ConsoleKey.Enter)
                    break;
                if (k.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0)
                        sb.Remove(sb.Length - 1, 1);
                }
                else if (k.KeyChar != '\u0000')
                {
                    sb.Append(k.KeyChar);
                }
            }
            Console.WriteLine();
            return sb.ToString();
        }

        public bool IsRetryable()
        {
            return true;
        }

        public string GetPassword()
        {
            Console.Write("Enter password (will not be echoed): ");
            return ReadPassword();
        }

        public string ChangePassword(string prompt, string language)
        {
            if (_enableChange)
            {
                if (string.IsNullOrEmpty(prompt))
                    prompt = "Enter new password (will not be echoed):";

                Console.WriteLine("Server asked you to change password");
                Console.Write($"{prompt} ");
                return ReadPassword();
            }

            return null;
        }
    }
}