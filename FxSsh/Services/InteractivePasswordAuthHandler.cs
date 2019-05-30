using System;
using System.Text;

namespace FxSsh.Services
{
    public class InteractivePasswordAuthHandler : IPasswordAuthHandler
    {
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
            if (string.IsNullOrEmpty(prompt))
                prompt = "Enter new password (will not be echoed):";
            
            Console.WriteLine("Server asked you to change password");
            Console.Write($"{prompt} ");
            return ReadPassword();
        }
    }
}