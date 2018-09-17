using AuthingDemo.Forms;
using AuthingSDK;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AuthingDemo
{
    static class Program
    {
        public static Authing authing = new Authing("5b9b79f2349e2d0001a5be67", "cb07a3091d5f39a89b518bf6b6d5094c");
        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            FrmLogin login = new FrmLogin();
            DialogResult result = login.ShowDialog();
            if(result == DialogResult.OK)
            {
                Application.Run(new FrmMain());
            }
        }
    }
}
