using AuthingSDK.exceptions;
using System.Collections.Generic;

namespace AuthingSDK.model
{
    public class Option
    {
        private Dictionary<string, object> option = new Dictionary<string, object>();

        public Option()
        {
        }
        public Option(string clientId)
        {
            option.Add("registerInClient", clientId);
        }

        public object GetBykey(string key)
        {
            return option[key];
        }

        public void UpdateValue(string key, object value)
        {
            if (option.ContainsKey(key))
            {
                option.Remove(key);
                option.Add(key, value);
            }
        }

        public void AddOption(string key, object value)
        {
            option.Add(key, value);
        }

        public bool CheckByKey(string key)
        {
            if (option.ContainsKey(key) && option[key] != null)
            {
                return true;
            }
            return false;
        }

        public bool CheckByKeys(string[] keys)
        {
            foreach (string key in keys)
            {
                if (!option.ContainsKey(key) || option[key] == null)
                {
                    throw new AuthingException("please make sure param " + key + " exist and not null");
                }
            }
            return true;
        }

        public Dictionary<string, object> GetOption()
        {
            return option;
        }

        internal void RemoveOption(string key)
        {
            if (option.ContainsKey(key) && option[key] != null)
            {
                option.Remove(key);
            }
            else
            {
                throw new AuthingException("please make sure param " + key + " exist and not null");
            }
        }
    }
}
