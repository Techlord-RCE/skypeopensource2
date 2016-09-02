using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;

namespace EpycsMessenger2
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Form1 TheForm = new Form1();
            //Application.Run(new Form1());
            TheForm.do_startup();
            Application.Run();
        }
    }
}
