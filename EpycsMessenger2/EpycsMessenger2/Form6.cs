using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace EpycsMessenger2 {
    public partial class Form6 : Form {
        public Form6() {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e) {
            //
            this.Close();
        }

        private void Form6_Load(object sender, EventArgs e) {
            //
            ;
            /*
            textBox1.Text = @"First stage:
1) Click ""Load contacts"".
2) Wait until all contacts loaded (or program crash :) )
3) Double click on some user in contacts list.
4) New form will appear. On this form click ""Refresh Vcard"" button.
5) Wait until resolving skypename to ip address ended.
6) Enter text to send in text area. And click ""Send"" button.
7) Wait until program will connect to relay node and if success, will establish connect to remote skypeuser.
8) If connect will success, msg send protocol starts exchange data. Wait until it finished.
9) If relay node reject connection for some reason, wait 30 seconds (2-3 minutes in worst cases) and click ""Send"" button again.
10) After message will successfully sended active textarea will clear and you message appear in ""Chat history"" area.

Second stage:
11) On remote skypeuser try to write some text to user from which you are are logged on. 
12) Click ""Recv MSG"" button on same form.
13) Wait until connection happens (if not, wait again 30 seconds and repeat) and message from remote skypeuser will appear in ""Chat history"" area.
14) Close will message form.
15) Try to double click on other skypeuser in contacts list. Click ""Refresh Vcard"" wait and try to send or recv message from him.
16) You also maybe have want to click on ""Resolve Users to IP"" button. But it will try resolv all users from you contact list and it can take long tome.
17) After it, button ""Check Skype Version of your Contacts"" maybe also was helpful if you want to know their skype versions. 
But also it can take long time because of program will try to initializr connect (with handshake only) to every skypeuser in your contact list to get his skype client version.
18) Thats all, folks! For now.

In future releases ""Recv MSG"" button will be removed. And functions like 'permanent connect' to parent-supernode will be added. You can speed up this process by donate to this project.
";
            */

        }


    }
}
