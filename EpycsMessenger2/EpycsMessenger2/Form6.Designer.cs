namespace EpycsMessenger2 {
    partial class Form6 {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing) {
            if (disposing && (components != null)) {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent() {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form6));
            this.label1 = new System.Windows.Forms.Label();
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.button1 = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(285, 9);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(115, 13);
            this.label1.TabIndex = 0;
            this.label1.Text = "Advanced instructions:";
            // 
            // textBox1
            // 
            this.textBox1.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox1.Location = new System.Drawing.Point(33, 29);
            this.textBox1.Multiline = true;
            this.textBox1.Name = "textBox1";
            this.textBox1.ReadOnly = true;
            this.textBox1.Size = new System.Drawing.Size(618, 386);
            this.textBox1.TabIndex = 2;
            this.textBox1.Text = @"First stage:
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
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(300, 425);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(85, 25);
            this.button1.TabIndex = 2;
            this.button1.Text = "OK";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // Form6
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(684, 462);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.textBox1);
            this.Controls.Add(this.label1);
            this.Name = "Form6";
            this.Text = "Form6";
            this.Load += new System.EventHandler(this.Form6_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox textBox1;
        private System.Windows.Forms.Button button1;
    }
}