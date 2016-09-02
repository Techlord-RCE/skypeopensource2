using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;


namespace EpycsMessenger2
{
    public partial class Form3 : Form
    {
        public Form3()
        {
            InitializeComponent();
        }

        [DllImport("skyauth4_dll.dll", EntryPoint = "skyauth", CharSet = CharSet.Ansi)]
        private static extern int EpycsLogin(string user, string pass);

        private long do_check_creds() {
            string auth_file;
            long length;
            //int ret;

            auth_file = "a_cred.txt";

            length = 0;
            if (File.Exists(auth_file)) {
                length = new System.IO.FileInfo(auth_file).Length;
            };

            return length;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string user;
            string pass;
            int ret;

            user = textBox1.Text;
            pass = textBox2.Text;
            if ((user.Length == 0) || (pass.Length == 0))
            {
                //richTextBox1.Text += "No login data provided.\n";
                MessageBox.Show("No login data provided.");
                return;
            };

            ret = 1;
            // no saved creds found, need login
            if (do_check_creds() == 0) {
                ret = EpycsLogin(user, pass);
            };
            
            if (ret == 1) {
                //richTextBox1.Text += "Login successful.\n";
                System.Media.SoundPlayer player = new System.Media.SoundPlayer(@".\\sound\\Skype_Connection.wav");
                player.Play();
                Form1.auth_login = user;
                Form1.auth_pass = pass;

                // do startup stuff at login
                Form1 main = this.Owner as Form1;
                main.on_login();
                main.Show();

                this.Hide();

                main.SetTextBoxSafe("Login successful.\n");

            }
            else
            {
                //richTextBox1.Text += "Login failed.\n";
                MessageBox.Show("Login failed.");
            };

        }

        private void Form3_Load(object sender, EventArgs e)
        {

            /*
            textBox1.Text = "themagicforyou";
            textBox2.Text = "adf123";
            */

            if (false) {
                textBox1.Text = "notnowagainplease";
                textBox2.Text = "adf123";
            }

        }


        private void Form3_FormClosing(object sender, FormClosingEventArgs e)
        {
            //Form1 main = this.Owner as Form1;

            Application.Exit();

            //this.Hide();
            //e.Cancel = true;
            //Exit();
        }

    
    }
}
