using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthingSDK.model
{
    public class PostEntity
    {
        public string query { get; set; }
        public Dictionary<string, object> variables { get; set; }

        public PostEntity(string query, Dictionary<string, object> variables)
        {
            this.query = query;
            this.variables = variables;
        }

        public PostEntity(string query, Option option)
        {
            this.query = query;
            this.variables = option.GetOption();
        }

        public PostEntity()
        {

        }
    }
}
