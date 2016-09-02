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
using System.Threading;

namespace EpycsMessenger2
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        public static string SelectedUser;
        private Form myForm2;
        private Form myForm3;
        private Form myForm4;
        private Form myForm5;
        private Form myForm6;

        public static string auth_login;
        public static string auth_pass;

        public int global_close = 0;

        public static Dictionary<string, string> dictionary =
                new Dictionary<string, string>();

        public static string my_addr = "";


        [DllImport("skycontact4_dll.dll", EntryPoint = "skycontact", CharSet = CharSet.Ansi)]
        private static extern int EpycsGetContacts(string user, string pass);


        // search users vcards
        [DllImport("skysearch4_dll.dll", EntryPoint = "skysearch_getslots", CharSet = CharSet.Ansi)]
        private static extern int EpycsSearchSlots(int argc, string[] argv, StringBuilder myip);
        
        [DllImport("skysearch4_dll.dll", EntryPoint = "skysearch_one", CharSet = CharSet.Ansi)]
        private static extern int EpycsSearchOneVcard(string user, StringBuilder vcard, int maxlen);

        [DllImport("skysearch4_dll.dll", EntryPoint = "skysearch_many", CharSet = CharSet.Ansi)]
        private static extern int EpycsSearchManyVcards(int argc, string[] argv, StringBuilder vcard, int maxlen);
        // end of search users vcards


        // relay connect and get remote user version
        [DllImport("skyrelay4_dll.dll", EntryPoint = "skyrelay", CharSet = CharSet.Ansi)]
        private static extern int EpycsGetVersion(string myip, string remote_name, string vcard, StringBuilder output);

        public void on_login() {
            myForm2 = new Form2();
            myForm2.Owner = this;

            //setup_listbox();
            CreateMyListView();
            SetupListImages();

            //Console.SetOut(new StreamWriter("Output.txt"));
            ShowConsoleWindow();
        }

        public void do_startup() {
            myForm3 = new Form3();
            myForm3.Owner = this;

            myForm3.Show();

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            ;
            /*
            myForm3 = new Form3();
            myForm3.Owner = this;
            */

            //System.Media.SoundPlayer player = new System.Media.SoundPlayer(@".\\sound\\Skype_Connection.wav");
            //player.Play();

            // hide main form
            /*
            BeginInvoke(new MethodInvoker(delegate
            {
                Hide();
            }));
            */

            // show login form
            //myForm3.Show();

            /*
            auth_login = "notnowagainplease";
            auth_pass = "adf123";
            */

            //textBox1.Text = "themagicforyou";
            //textBox2.Text = "adf123";
        }

        
        private void UpdateOnlineList()
        {
            string user;

            foreach (ListViewItem itemLV in listView1.Items) {                
                user = itemLV.Text;
                if (dictionary.ContainsKey(user)) {
                    itemLV.ImageIndex = 1;
                } else {
                    itemLV.ImageIndex = 0;
                };
            }

        }

        private void SetupListImages() {

            ImageList imageListSmall = new ImageList();
            imageListSmall.Images.Add(Bitmap.FromFile("pics\\MySmallImage1.bmp"));
            imageListSmall.Images.Add(Bitmap.FromFile("pics\\MySmallImage2.bmp"));
        
            listView1.SmallImageList = imageListSmall;
        }

        private void AddItemToList(string username) {
            ListViewItem item = new ListViewItem(username, 0);
            item.SubItems.Add(" ");
            listView1.Items.Add(item);
        }

        private void CreateMyListView() {
            listView1.View = View.Details;
            listView1.FullRowSelect = true;
            listView1.Sorting = SortOrder.Ascending;
            //listView1.HeaderStyle = ColumnHeaderStyle.None;

            listView1.Columns.Add("Users", 110, HorizontalAlignment.Left);
            listView1.Columns.Add("Version", -2, HorizontalAlignment.Left);
        }


        // Console Stuff
        public void ShowConsoleWindow()
        {
            var handle = GetConsoleWindow();

            if (handle == IntPtr.Zero)
            {
                AllocConsole();
                handle = GetConsoleWindow();
            }
            else
            {
                ShowWindow(handle, SW_SHOW);
            }

            int windowTop = this.Top;
            int windowLeft = this.Left;

            int windowHeight = this.Height;
            int windowWidth = this.Width;

            int xpos = windowLeft + windowWidth;
            int ypos = windowTop;

            SetWindowPos(handle, 0, xpos, ypos, 0, 0, SWP_NOSIZE);

            System.Console.WriteLine("Debug window.");
            System.Console.WriteLine("Do not close.");

        }
        public void HideConsoleWindow()
        {
            var handle = GetConsoleWindow();

            ShowWindow(handle, SW_HIDE);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AllocConsole();

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll", EntryPoint = "SetWindowPos")]
        public static extern IntPtr SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int x, int Y, int cx, int cy, int wFlags);
        
        const int SWP_NOSIZE = 0x0001;
        const int SW_HIDE = 0;
        const int SW_SHOW = 5;
        // End of Console Stuff


        
        private void setup_listbox() {
            AddItemToList("user1");
            AddItemToList("user2");
            AddItemToList("user3");
        }

        private void clear_listbox() {
            /*
            foreach (ListViewItem itemLV in listView1.Items) {
                argv[argc] = itemLV.Text;
                argc += 1;
            };
            */
            listView1.Items.Clear();
        }

        private void fill_listbox()
        {
            string[] lines;

            try {
                lines = System.IO.File.ReadAllLines(@"contacts.txt");
            } catch (Exception e) {
                richTextBox1.Text += "The file could not be read:\n";
                richTextBox1.Text += e.Message + "\n";
                return;
            }

            foreach (string line in lines) {
                if (line.StartsWith("p/")) {
                    continue;
                };
                if (line.StartsWith("u/+7")) {
                    continue;
                };
                if (line.StartsWith("u/")) {
                    AddItemToList(line.Substring(2));
                };
            }

        }

        private void button2_Click(object sender, EventArgs e)
        {
            string contacts_file;
            long length;

            string user;
            string pass;
            int ret;

            clear_listbox();

            contacts_file = "contacts.txt";

            user = auth_login;
            pass = auth_pass;
            if ((user.Length == 0) || (pass.Length == 0))
            {
                richTextBox1.Text += "No login data provided.\n";
                return;
            };

            length = 0;
            if (File.Exists(contacts_file)) {
                length = new System.IO.FileInfo(contacts_file).Length;
            };

            if (length > 0) {
                richTextBox1.Text += "Load contacts from cache.\n";
                fill_listbox();
                return;
            }

            richTextBox1.Text += "No contacts cache file found. Do actual request.\n";
            ret = EpycsGetContacts(user, pass);

            if (ret == 1)
            {
                richTextBox1.Text += "Load contacts successful.\n";
                fill_listbox();
            }
            else
            {
                richTextBox1.Text += "Load contacts failed.\n";
            };


        }



        private void listView1_MouseDoubleClick(object sender, MouseEventArgs e) {

            SelectedUser = "";
            if (listView1.SelectedItems.Count > 0) {
                SelectedUser = listView1.SelectedItems[0].Text;
            } else {
                richTextBox1.Text += "No selected item on doubleclick\n";
                return;
            };

            richTextBox1.Text += "Creating window for chat with " + SelectedUser + "\n";

            myForm2.Show();
            myForm2.Focus();

            button3.Enabled = true;
            button4.Enabled = true;

        }


        private int save_login_to_file(){
            //todo
            return 0;
        }

        private int load_login_from_file(){
            //todo
            return 0;
        }

        public int do_prepare() 
        {
            int argc;
            string[] argv = new String[1000];
            int ret;
            StringBuilder myip = new StringBuilder(1000);

            if (listView1.Items.Count == 0) {
                richTextBox1.Text += "Error, no elements in contact list\n";
                return -1;
            };

            argc = 0;
            foreach (ListViewItem itemLV in listView1.Items) {
                argv[argc] = itemLV.Text;
                argc += 1;
            };
            richTextBox1.Text += "Count: " + argc + "\n";

            ret = EpycsSearchSlots(argc, argv, myip);

            my_addr = myip.ToString();
            richTextBox1.Text += "MY_ADDR: " + my_addr + "\n";

            return ret;    
        }

        public int do_prepare_for_one(string user)
        {
            int argc;
            string[] argv = new String[1000];
            int ret;
            StringBuilder myip = new StringBuilder(1000);

            argc = 0;
            argv[argc] = user;
            argc += 1;

            //richTextBox1.Text += "Count: " + argc + "\n";
            SetTextBoxSafe("Count: " + argc + "\n");

            ret = EpycsSearchSlots(argc, argv, myip);

            my_addr = myip.ToString();
            //richTextBox1.Text += "MY_ADDR: " + my_addr + "\n";
            //SetTextBoxSafe("MY_ADDR: " + my_addr + "\n");

            return ret;
        }

        public void SetTextBoxSafe(string newText)
        {
            if (richTextBox1.InvokeRequired) richTextBox1.Invoke(new Action<string>((s) => richTextBox1.Text += s), newText);
            else richTextBox1.Text += newText;

        }

        public void do_resolv(string user) {
            // for returned buffer to write in
            StringBuilder vcard_buf = new StringBuilder(4096);
            string vcard_str;
            //string vcard_s;
            //string[] vcards;
            int ret;
            int maxlen = 4096;
            //int idx;

            SetTextBoxSafe("Start resolv for user: " + user + "\n");

            ret = EpycsSearchOneVcard(user, vcard_buf, maxlen);
            
            vcard_str = vcard_buf.ToString();

            if (!dictionary.ContainsKey(user)) {
                dictionary.Add(user, vcard_str);
            } else {
                dictionary[user] = vcard_str;
            };

            //richTextBox1.Text += "Vcards loaded for user: " + user + "\n Vcards:" + vcard_str + "\n";

            SetTextBoxSafe("Vcards loaded for user: " + user + "\n Vcards:" + vcard_str + "\n");

            /*
            vcards = vcard_str.Split('\n');
            foreach (string vcard in vcards) {                
                if (vcard.IndexOf("-s0.0.0.0") >= 0) {
                    //richTextBox1.Text += "Vcard:" + vcard + "\n";
                    SetTextBoxSafe("Vcard:" + vcard + "\n");
                } else {
                    //richTextBox1.Text += "Actual Vcard: " + vcard + "\n";
                    SetTextBoxSafe("Actual Vcard: " + vcard + "\n");
                    idx = vcard.IndexOf(" - ");
                    if (idx > 0) {
                        vcard_s = vcard.Substring(idx + 3);
                        if (!dictionary.ContainsKey(user)) {
                            dictionary.Add(user, vcard_s);
                        } else {
                            //richTextBox1.Text += "Dublicate username find: " + user + "\n";
                            SetTextBoxSafe("Dublicate username find: " + user + "\n");
                            dictionary[user] = vcard_s;
                        };
                    };
                };

            };
            */


        }

        private void button3_Click(object sender, EventArgs e)
        {
            string user;
            int ret;

            richTextBox1.Text += "Users Resolv start prepare...\n";

            ret = do_prepare();
            if (ret == -1) {
                return ;
            }

            richTextBox1.Text += "Users Resolv prepare done.\n";

            foreach (ListViewItem itemLV in listView1.Items) {
                user = itemLV.Text;
                do_resolv(user);
                
                //start_thread(user);
                //UpdateOnlineList();
            };
            
            UpdateOnlineList();

            return;
        }

        private int do_prepare2() {
            int argc;
            string[] argv = new String[1000];
            int ret;
            StringBuilder myip = new StringBuilder(1000);

            argc = 2;
            argv[0] = "notnowagainnplease";
            argv[1] = "xot_iam";

            ret = EpycsSearchSlots(argc, argv, myip);

            return ret;
        }

        private void temp_test() {
            string user;

            do_prepare2();

            user = "notnowagainplease";
            do_resolv(user);
            user = "xot_iam";
            do_resolv(user);

        }

        private void dump_list() {
            List<string> list = new List<string>(dictionary.Keys);

            richTextBox1.Text += "List:\n";
            foreach (string k in list) {
                richTextBox1.Text += "[\""+k+"\"] --> " + dictionary[k] + "\n";
            };
        }

        private void check_versions() {
            string myip;
            string remote_name;
            string vcard;
            StringBuilder output = new StringBuilder(1000);
            string version;
            List<string> list = new List<string>(dictionary.Keys);

            if (my_addr.Length == 0) {
                richTextBox1.Text += "MY_ADDR unknown.\n";
                return;
            };
            myip = my_addr;

            richTextBox1.Text += "Start checking skype versions.\n";

            foreach (string k in list) {
                richTextBox1.Text += "Checking: [\"" + k + "\"] --> " + dictionary[k] + "\n";
            
                remote_name = k;
                vcard = dictionary[k];

                // clean output buffer
                output.Clear();
                //output.Length=0;

                EpycsGetVersion(myip, remote_name, vcard, output);
                version = output.ToString();
                richTextBox1.Text += "Version: " + version + "\n";

                SetContactVersion(remote_name, version);
            };


        }


        private void SetContactVersion(string user, string version) {
            foreach (ListViewItem itemLV in listView1.Items) {
                if (itemLV.SubItems[0].Text == user) {
                    itemLV.SubItems[1].Text = version;
                    //richTextBox1.Text += "Userinfo: " + userinfo + "\n";
                    return;
                };
            };
        }

        /*
        public void WorkThreadFunction(string user) {
            try {
                // do any background work
                do_resolv(user);
            }
            catch (Exception ex) {
                // log errors
                richTextBox1.Text += "Creating or running Thread error\n";
            }
        }
        */

        /*
        private void start_thread(string user) {
            var thread = new Thread(
                   () => WorkThreadFunction(user));
            thread.Start();
            //Thread t = new Thread(new ParameterizedThreadStart(WorkThreadFunction));
            //t.Start(user);
        }
        */

        private void button4_Click(object sender, EventArgs e)
        {
            //SetContactVersion("echo123", "1.1.1.1");
            //get_version_test();

            check_versions();

            //temp_test();
            dump_list();
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            this.global_close = 1;

            Application.Exit();
            
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e) {
            //
            //Form frmAbout = new Form();
            myForm4 = new Form4();
            myForm4.Owner = this;

            myForm4.ShowDialog();
            //myForm4.Show();

        }

        private void usageToolStripMenuItem1_Click(object sender, EventArgs e) {
            //
            //
            myForm5 = new Form5();
            myForm5.Owner = this;

            myForm5.Show();

        }

        private void advancedToolStripMenuItem_Click(object sender, EventArgs e) {
            //
            //
            myForm6 = new Form6();
            myForm6.Owner = this;

            myForm6.Show();
        }


    }
}
