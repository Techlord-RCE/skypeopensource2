using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace EpycsMessenger2 {
    public partial class Form5 : Form {
        public Form5() {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e) {
            //
            this.Close();

        }

        private void Form5_Load(object sender, EventArgs e) {
            ;
           /*
             textBox1.Text =
@"1) Click ""Load contacts"". Wait until all contacts loaded.

2) Double click on some user in contacts list.

3) New form will appear. On this form click ""Refresh Vcard"" button.

4) Wait until resolving skypename to ip address ended.

5) Enter text to send in text area. And click ""Send"" button.

6) Wait until program will connect to relay node and if success, 
will establish connect to remote skypeuser.

7) If connect will success, msg send protocol starts exchange data. 
Wait until it finished.

8) If relay node reject connection for some reason, wait 30 seconds 
(2-3 minutes in worst cases) and click ""Send"" button again.

9) After message will successfully sended active textarea will clear 
and you message appear in ""Chat history"" area.
";
            */


        }

    }
}
