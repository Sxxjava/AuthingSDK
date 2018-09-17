using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AuthingDemo.Forms
{
    public partial class FrmLogin : Form
    {
        public FrmLogin()
        {
            InitializeComponent();
        }

        private void btn_login_Click(object sender, EventArgs e)
        {
            string email = input_email.Text.Trim();
            string password = input_password.Text.Trim();
            Program.authing.Login(email,password);
        }

        private void btn_register_Click(object sender, EventArgs e)
        {
            string email = input_email.Text.Trim();
            string password = input_password.Text.Trim();
            Program.authing.Register(email, password);
        }
    }
}
