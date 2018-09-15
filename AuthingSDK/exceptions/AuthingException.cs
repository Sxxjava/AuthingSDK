using System;

namespace AuthingSDK.exceptions
{
    [Serializable]
    public class AuthingException : ApplicationException
    {
        public AuthingException(string message) : base(message)
        {

        }
        public AuthingException(string message, Exception inner) : base(message, inner)
        {

        }
    }
}
