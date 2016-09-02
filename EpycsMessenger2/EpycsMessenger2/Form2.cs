using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace EpycsMessenger2
{
    public partial class Form2 : Form
    {

        public Form2()
        {
            InitializeComponent();
        }

        [DllImport("goodsendrelay4_dll.dll", EntryPoint = "relaysend", CharSet = CharSet.Unicode)]
        private static extern int EpycsRelaySendMsg(string myip, string username, string uservcard, string static_msg);

        [DllImport("goodrecvrelay4_dll.dll", EntryPoint = "relayrecv", CharSet = CharSet.Unicode)]
        private static extern int EpycsRelayRecvMsg(string myip, string username, string uservcard, StringBuilder vcard);

        [DllImport("sqldbread2_dll.dll", EntryPoint = "load_chathistory", CharSet = CharSet.Unicode)]
        private static extern int EpycsLoadChatHistory(string localname, string remotename, StringBuilder chathistory);

        /*
        [DllImport("goodrecvrelay4_dll.dll", EntryPoint = "relayrecv", CharSet = CharSet.Ansi)]

        [DllImport("setcharset.dll", EntryPoint = "charsetsend", CharSet = CharSet.Unicode)]
        private static extern int EpycsRelaySendMsg(string myip, string username, string uservcard, string static_msg);
        */

        private void RefreshChat() {
            string localname;
            string remotename;
            StringBuilder chathistory = new StringBuilder(4096);

            localname = Form1.auth_login;
            remotename = Form1.SelectedUser;

            EpycsLoadChatHistory(localname, remotename, chathistory);

            richTextBox3.Text = chathistory.ToString();
        }

        private void Form2_Load(object sender, EventArgs e)
        {
            string username;
            username = Form1.SelectedUser;
            textBox1.Text = username;
            if (Form1.dictionary.ContainsKey(username))
            {
                textBox2.Text = Form1.dictionary[username];
            } else {
                textBox2.Text = "";
            };
            richTextBox1.Text = "";

            RefreshChat();
        }

        private void Form2_Activated(object sender, EventArgs e)
        {
            string username;
            username = Form1.SelectedUser;
            if (username != textBox1.Text) {
                richTextBox1.Text = "";
            };
            textBox1.Text = username;
            if (Form1.dictionary.ContainsKey(username)) {
                textBox2.Text = Form1.dictionary[username];
            } else {
                textBox2.Text = "";
            };

            RefreshChat();
        }

        private void Form2_FormClosing(object sender, FormClosingEventArgs e)
        {
            this.Hide();

            Form1 main = this.Owner as Form1;
            if (main.global_close == 0) {
                e.Cancel = true;
            }

        }

  
        // msg send
        private void button1_Click(object sender, EventArgs e) 
        {
            string myip;
            string username;
            string uservcard;
            string msg;
            int ret;

            /*
            //username = "xot_iam" + ":192.168.1.110:5322";
            username = "notnowagainplease";
            uservcard = "0xe03e31ae403ae012-s-s65.55.223.25:40021-r95.52.236.102:57608-l192.168.1.75:57608";
            */
            
            // input data for relaymsg function
            myip = Form1.my_addr;
            username = textBox1.Text;
            uservcard = "";
            /*
            if (Form1.dictionary.ContainsKey(username)) {
                uservcard = Form1.dictionary[username];
            };
            */
            uservcard = textBox2.Text;
            msg = richTextBox1.Text;
            // end of input data

            richTextBox2.Text += "Username: " + username + "\n";
            richTextBox2.Text += "Uservcard: " + uservcard + "\n";

            // input check
            if (myip.Length == 0) {
                richTextBox2.Text += "My IP not found.\n";
                //return;
            };
            if (username.Length == 0) {
                richTextBox2.Text += "Something weird, username not found.\n";
                return;
            };
            if (uservcard.Length == 0) {
                richTextBox2.Text += "No suitable vcard found for this user.\n";
                richTextBox2.Text += "Try to resolve users first.\n";
                //return;
            };
            if (msg.Length == 0) {
                richTextBox2.Text += "No message entered.\n";
                return;
            };
            // end of input check

            ret = EpycsRelaySendMsg(myip, username, uservcard, msg);

            if (ret == 1) {
                richTextBox2.Text += "Message send successful.\n";
                // remove sended message from send textbox
                richTextBox1.Text = "";
                RefreshChat();
            }
            if (ret == -10)
            {
                richTextBox2.Text += "Supernode relay connect fail. Message send fail.\n";
            }
            if (ret <= 0)
            {
                richTextBox2.Text += "Message send failed. Ret code:" + ret.ToString() + "\n";
            };

        }

        //msg recv
        private void button2_Click(object sender, EventArgs e)
        {
            // for returned buffer to write in
            StringBuilder msg_buf = new StringBuilder(4096);

            string myip;
            string username;
            string uservcard;
            int ret;

           
            // input data for relaymsg function
            myip = Form1.my_addr;
            username = textBox1.Text;
            uservcard = "";
            /*
            if (Form1.dictionary.ContainsKey(username))
            {
                uservcard = Form1.dictionary[username];
            };
            */
            uservcard = textBox2.Text;
            // end of input data

            /*
            username = "themagicforyou";
            uservcard = "0xdb8bd323dde03347-d-s65.55.223.41:40006-r117.3.37.199:14410-l192.168.1.135:14410";
            myip = "117.3.37.199";
            */

            richTextBox2.Text += "Username: " + username + "\n";
            richTextBox2.Text += "Uservcard: " + uservcard + "\n";

            // input check
            if (myip.Length == 0)
            {
                richTextBox2.Text += "My IP not found.\n";
                return;
            };
            if (username.Length == 0)
            {
                richTextBox2.Text += "Something weird, username not found.\n";
                return;
            };
            if (uservcard.Length == 0)
            {
                richTextBox2.Text += "No suitable vcard found for this user.\n";
                richTextBox2.Text += "Try to resolve users first.\n";
                return;
            };
            // end of input check

            ret = EpycsRelayRecvMsg(myip, username, uservcard, msg_buf);

            if (ret == 1) {
                richTextBox2.Text += "Message recv successful.\n";
                // refreshing chat window, after successful recv message
                RefreshChat();
            }
            if ((ret == 0) || (ret == -1)) {
                richTextBox2.Text += "Message recv failed.\n";
            };
            if (ret == -10) {
                richTextBox2.Text += "Supernode relay connect fail. Message recv fail.\n";
            }

            richTextBox2.Text += "MSG: " + msg_buf + "\n";
            //richTextBox2.Text = msg_buf.ToString();
        
        }

        // vcard refresh function
        private void button3_Click(object sender, EventArgs e)
        {
            string user;

            user = textBox1.Text;
            if (user.Length == 0)
            {
                richTextBox2.Text += "Something weird, username not found.\n";
                return;
            };

            Form1 main = this.Owner as Form1;

            /*
            if (Form1.my_addr.Length == 0) {
                main.do_prepare_for_one(user);
            };
            */

            main.do_prepare_for_one(user);

            main.do_resolv(user);

            // show new vcard refresh
            if (Form1.dictionary.ContainsKey(user)) {
                textBox2.Text = Form1.dictionary[user];
            };


        }

   
    
    }
}
