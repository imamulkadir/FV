using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Xml;
using Microsoft.Win32;
using System.Reflection;

[assembly: AssemblyTitle("FV Folder Access Control")]
[assembly: AssemblyDescription("FV Folder Access Control")]
[assembly: AssemblyCompany("PentaPet")]
[assembly: AssemblyProduct("FV")]
[assembly: AssemblyCopyright("Copyright © 2026 Imamul Kadir. All rights reserved.")]

namespace FVApp
{
    [DataContract]
    sealed class AuthRecord
    {
        [DataMember(Name="scheme", EmitDefaultValue=false)] public string Scheme;
        [DataMember(Name="salt", EmitDefaultValue=false)] public string Salt;
        [DataMember(Name="verifier", EmitDefaultValue=false)] public string Verifier;
    }

    [DataContract]
    sealed class LockedRecord
    {
        [DataMember(Name="path")] public string Path;
        [DataMember(Name="original_sddl")] public string OriginalSddl;
        [DataMember(Name="user_sid", EmitDefaultValue=false)] public string UserSid;
    }

    [DataContract]
    sealed class AppConfig
    {
        [DataMember(Name="version")] public int Version = 3;
        [DataMember(Name="locked_folders")] public Dictionary<string, LockedRecord> Locked = new Dictionary<string, LockedRecord>();
        [DataMember(Name="auth", EmitDefaultValue=false)] public AuthRecord Auth;
    }

    static class Store
    {
        internal static readonly string DirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VaultFolderACL");
        internal static readonly string ConfigPath = Path.Combine(DirectoryPath, "config.json");

        static DataContractJsonSerializer Serializer()
        {
            return new DataContractJsonSerializer(typeof(AppConfig), new DataContractJsonSerializerSettings { UseSimpleDictionaryFormat = true });
        }

        internal static AppConfig Load()
        {
            System.IO.Directory.CreateDirectory(DirectoryPath);
            if (!File.Exists(ConfigPath)) return new AppConfig();
            using (FileStream stream = File.OpenRead(ConfigPath))
            {
                AppConfig config = (AppConfig)Serializer().ReadObject(stream);
                if (config == null) config = new AppConfig();
                if (config.Locked == null) config.Locked = new Dictionary<string, LockedRecord>();
                config.Version = 3;
                return config;
            }
        }

        internal static void Save(AppConfig config)
        {
            System.IO.Directory.CreateDirectory(DirectoryPath);
            string temp = ConfigPath + ".tmp";
            using (FileStream stream = File.Create(temp)) Serializer().WriteObject(stream, config);
            if (File.Exists(ConfigPath))
            {
                try { File.Replace(temp, ConfigPath, null); return; }
                catch (IOException) { File.Delete(ConfigPath); }
            }
            File.Move(temp, ConfigPath);
        }
    }

    static class Passwords
    {
        const string Scheme = "pbkdf2-sha1-200000-v1";
        const int Iterations = 200000;

        internal static bool Current(AppConfig c)
        {
            return c.Auth != null && c.Auth.Scheme == Scheme && !String.IsNullOrEmpty(c.Auth.Salt) && !String.IsNullOrEmpty(c.Auth.Verifier);
        }

        static byte[] Derive(string password, byte[] salt)
        {
            using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password, salt, Iterations)) return kdf.GetBytes(32);
        }

        internal static void Set(AppConfig c, string password)
        {
            if (password == null || password.Length < 8) throw new ArgumentException("Use at least 8 characters.");
            byte[] salt = new byte[16];
            using (RandomNumberGenerator random = RandomNumberGenerator.Create()) random.GetBytes(salt);
            c.Auth = new AuthRecord { Scheme = Scheme, Salt = Convert.ToBase64String(salt), Verifier = Convert.ToBase64String(Derive(password, salt)) };
            c.Version = 3;
            Store.Save(c);
        }

        internal static void Verify(AppConfig c, string password)
        {
            if (!Current(c)) throw new InvalidOperationException("A new FV master password is required.");
            byte[] expected = Convert.FromBase64String(c.Auth.Verifier);
            byte[] actual = Derive(password, Convert.FromBase64String(c.Auth.Salt));
            int difference = expected.Length ^ actual.Length;
            for (int i = 0; i < Math.Min(expected.Length, actual.Length); i++) difference |= expected[i] ^ actual[i];
            if (difference != 0) throw new ArgumentException("Incorrect master password.");
        }
    }

    static class Acl
    {
        internal static string Sid { get { return WindowsIdentity.GetCurrent().User.Value; } }

        internal static string Read(string path)
        {
            DirectorySecurity security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
            return security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        }

        internal static void Restore(string path, string sddl)
        {
            DirectoryInfo directory = new DirectoryInfo(path);
            DirectorySecurity security = directory.GetAccessControl(AccessControlSections.Access);
            security.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
            directory.SetAccessControl(security);
        }

        internal static void Lock(string path, string sidText)
        {
            DirectoryInfo directory = new DirectoryInfo(path);
            DirectorySecurity security = directory.GetAccessControl(AccessControlSections.Access);
            SecurityIdentifier sid = new SecurityIdentifier(sidText);
            List<FileSystemAccessRule> stale = new List<FileSystemAccessRule>();
            foreach (AuthorizationRule authorization in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            {
                FileSystemAccessRule rule = authorization as FileSystemAccessRule;
                SecurityIdentifier identity = rule == null ? null : rule.IdentityReference as SecurityIdentifier;
                if (identity != null && identity.Value == sidText && rule.AccessControlType == AccessControlType.Deny) stale.Add(rule);
            }
            foreach (FileSystemAccessRule rule in stale) security.RemoveAccessRuleSpecific(rule);

            FileSystemRights rights = FileSystemRights.ReadData | FileSystemRights.ListDirectory | FileSystemRights.ReadAttributes |
                FileSystemRights.ReadExtendedAttributes | FileSystemRights.ReadPermissions | FileSystemRights.CreateFiles |
                FileSystemRights.CreateDirectories | FileSystemRights.WriteData | FileSystemRights.AppendData |
                FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes | FileSystemRights.ExecuteFile |
                FileSystemRights.Traverse | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles;
            security.AddAccessRule(new FileSystemAccessRule(sid, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Deny));
            directory.SetAccessControl(security);
        }
    }

    static class SvgIcons
    {
        static float Number(XmlNode node, string name)
        {
            return Single.Parse(node.Attributes[name].Value, CultureInfo.InvariantCulture);
        }

        static float PathNumber(MatchCollection tokens, ref int index)
        {
            if (index >= tokens.Count || Char.IsLetter(tokens[index].Value[0])) throw new FormatException("Invalid SVG path data.");
            return Single.Parse(tokens[index++].Value, CultureInfo.InvariantCulture);
        }

        static GraphicsPath ReadPath(string data)
        {
            MatchCollection tokens = Regex.Matches(data, @"[-+]?(?:\d*\.\d+|\d+\.?)(?:[eE][-+]?\d+)?|[A-Za-z]");
            GraphicsPath path = new GraphicsPath(FillMode.Alternate);
            PointF current = new PointF(), start = new PointF();
            char command = '\0'; int index = 0;
            while (index < tokens.Count)
            {
                if (Char.IsLetter(tokens[index].Value[0]))
                {
                    command = tokens[index++].Value[0];
                    if (command == 'Z' || command == 'z') { path.CloseFigure(); current = start; continue; }
                }
                bool relative = Char.IsLower(command);
                switch (Char.ToUpperInvariant(command))
                {
                    case 'M':
                    {
                        float x = PathNumber(tokens, ref index), y = PathNumber(tokens, ref index);
                        if (relative) { x += current.X; y += current.Y; }
                        current = start = new PointF(x, y); path.StartFigure();
                        command = relative ? 'l' : 'L';
                        break;
                    }
                    case 'L':
                    {
                        float x = PathNumber(tokens, ref index), y = PathNumber(tokens, ref index);
                        if (relative) { x += current.X; y += current.Y; }
                        PointF next = new PointF(x, y); path.AddLine(current, next); current = next;
                        break;
                    }
                    case 'H':
                    {
                        float x = PathNumber(tokens, ref index); if (relative) x += current.X;
                        PointF next = new PointF(x, current.Y); path.AddLine(current, next); current = next;
                        break;
                    }
                    case 'V':
                    {
                        float y = PathNumber(tokens, ref index); if (relative) y += current.Y;
                        PointF next = new PointF(current.X, y); path.AddLine(current, next); current = next;
                        break;
                    }
                    case 'C':
                    {
                        float x1 = PathNumber(tokens, ref index), y1 = PathNumber(tokens, ref index);
                        float x2 = PathNumber(tokens, ref index), y2 = PathNumber(tokens, ref index);
                        float x = PathNumber(tokens, ref index), y = PathNumber(tokens, ref index);
                        if (relative) { x1 += current.X; y1 += current.Y; x2 += current.X; y2 += current.Y; x += current.X; y += current.Y; }
                        PointF next = new PointF(x, y); path.AddBezier(current, new PointF(x1, y1), new PointF(x2, y2), next); current = next;
                        break;
                    }
                    default: path.Dispose(); throw new NotSupportedException("Unsupported SVG path command: " + command);
                }
            }
            return path;
        }

        internal static Bitmap Load(string resourceName, int size)
        {
            XmlDocument document = new XmlDocument();
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
            {
                if (stream == null) throw new InvalidOperationException("Missing icon resource: " + resourceName);
                document.Load(stream);
            }

            Bitmap bitmap = new Bitmap(size, size);
            string colorValue = document.DocumentElement.GetAttribute("color");
            Color iconColor = String.IsNullOrEmpty(colorValue)
                ? Color.FromArgb(45, 45, 45)
                : ColorTranslator.FromHtml(colorValue);
            using (Graphics graphics = Graphics.FromImage(bitmap))
            using (Pen darkPen = new Pen(iconColor, 1.8f))
            using (Pen lightPen = new Pen(Color.White, 1.3f))
            using (Brush darkBrush = new SolidBrush(iconColor))
            using (Brush lightBrush = new SolidBrush(Color.White))
            {
                graphics.SmoothingMode = SmoothingMode.AntiAlias;
                graphics.ScaleTransform(size / 24f, size / 24f);
                darkPen.StartCap = darkPen.EndCap = LineCap.Round;
                darkPen.LineJoin = LineJoin.Round;

                foreach (XmlNode node in document.DocumentElement.ChildNodes)
                {
                    if (node.Name == "path")
                    {
                        using (GraphicsPath path = ReadPath(node.Attributes["d"].Value))
                        {
                            Color pathColor = iconColor;
                            XmlAttribute fill = node.Attributes["fill"];
                            if (fill != null && fill.Value != "none") pathColor = ColorTranslator.FromHtml(fill.Value);
                            using (Brush pathBrush = new SolidBrush(pathColor)) graphics.FillPath(pathBrush, path);
                        }
                    }
                    else if (node.Name == "polyline")
                    {
                        string[] values = node.Attributes["points"].Value.Split(new char[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
                        PointF[] points = new PointF[values.Length / 2];
                        for (int i = 0; i < points.Length; i++) points[i] = new PointF(Single.Parse(values[i * 2], CultureInfo.InvariantCulture), Single.Parse(values[i * 2 + 1], CultureInfo.InvariantCulture));
                        graphics.DrawLines(darkPen, points);
                    }
                    else if (node.Name == "rect")
                    {
                        RectangleF rectangle = new RectangleF(Number(node, "x"), Number(node, "y"), Number(node, "width"), Number(node, "height"));
                        graphics.FillRectangle(darkBrush, rectangle); graphics.DrawRectangle(darkPen, rectangle.X, rectangle.Y, rectangle.Width, rectangle.Height);
                    }
                    else if (node.Name == "circle")
                    {
                        float radius = Number(node, "r"), x = Number(node, "cx") - radius, y = Number(node, "cy") - radius;
                        graphics.FillEllipse(lightBrush, x, y, radius * 2, radius * 2);
                    }
                    else if (node.Name == "line")
                    {
                        graphics.DrawLine(lightPen, Number(node, "x1"), Number(node, "y1"), Number(node, "x2"), Number(node, "y2"));
                    }
                }
            }
            return bitmap;
        }
    }

    enum PasswordMode { Login, Create, Change }

    static class Ui
    {
        internal static readonly Color Accent = Color.FromArgb(89, 70, 210);
        internal static readonly Color AccentHover = Color.FromArgb(76, 58, 190);
        internal static readonly Color Surface = Color.White;
        internal static readonly Color Canvas = Color.FromArgb(247, 247, 249);
        internal static readonly Color Border = Color.FromArgb(218, 218, 224);
        internal static readonly Color Muted = Color.FromArgb(103, 103, 112);

        internal static void StyleButton(Button button, bool primary)
        {
            button.FlatStyle = FlatStyle.System;
            button.UseVisualStyleBackColor = true;
            button.BackColor = SystemColors.Control;
            button.ForeColor = SystemColors.ControlText;
        }

        internal static void StyleIconButton(Button button)
        {
            button.FlatStyle = FlatStyle.Standard;
            button.UseVisualStyleBackColor = true;
            button.BackColor = SystemColors.Control;
        }
    }

    sealed class PasswordDialog : Form
    {
        readonly PasswordMode mode;
        readonly TextBox current;
        readonly TextBox password;
        readonly TextBox confirm;
        internal string CurrentPassword { get { return current == null ? "" : current.Text; } }
        internal string PasswordValue { get { return password.Text; } }

        internal PasswordDialog(PasswordMode mode)
        {
            this.mode = mode;
            Text = mode == PasswordMode.Login ? "Unlock FV" : mode == PasswordMode.Create ? "Create master password" : "Change master password";
            Icon = Program.AppIcon; Font = SystemFonts.MessageBoxFont; BackColor = Ui.Canvas; FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false; ShowInTaskbar = false; StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(420, mode == PasswordMode.Change ? 213 : 173);
            int top = 18;
            if (mode == PasswordMode.Change) { current = AddRow("Current password:", top); top += 36; }
            password = AddRow(mode == PasswordMode.Login ? "Master password:" : "New password:", top); top += 36;
            if (mode != PasswordMode.Login) { confirm = AddRow("Confirm password:", top); top += 36; }
            CheckBox show = new CheckBox { Text = mode == PasswordMode.Change ? "Show passwords" : "Show password", AutoSize = true, Location = new Point(132, top + 2) };
            show.CheckedChanged += delegate { bool hidden = !show.Checked; password.UseSystemPasswordChar = hidden; if (current != null) current.UseSystemPasswordChar = hidden; if (confirm != null) confirm.UseSystemPasswordChar = hidden; };
            Controls.Add(show);
            Button ok = new Button { Text = mode == PasswordMode.Login ? "Unlock" : "OK", Size = new Size(82, 27), Location = new Point(230, ClientSize.Height - 43) };
            Ui.StyleButton(ok, true); ok.Click += ValidateInput; Controls.Add(ok);
            Button cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Size = new Size(82, 27), Location = new Point(320, ClientSize.Height - 43) };
            Ui.StyleButton(cancel, false); Controls.Add(cancel); AcceptButton = ok; CancelButton = cancel;
        }

        TextBox AddRow(string text, int top)
        {
            Controls.Add(new Label { Text = text, AutoSize = true, Location = new Point(16, top + 4) });
            TextBox box = new TextBox { Location = new Point(132, top), Size = new Size(270, 24), UseSystemPasswordChar = true };
            Controls.Add(box); return box;
        }

        void ValidateInput(object sender, EventArgs e)
        {
            string error = null;
            if (mode == PasswordMode.Change && String.IsNullOrEmpty(CurrentPassword)) error = "Enter your current password.";
            else if (mode == PasswordMode.Login && String.IsNullOrEmpty(PasswordValue)) error = "Enter your master password.";
            else if (mode != PasswordMode.Login && PasswordValue.Length < 8) error = "Use at least 8 characters.";
            else if (mode != PasswordMode.Login && PasswordValue != confirm.Text) error = "Passwords do not match.";
            if (error != null) { MessageBox.Show(this, error, "FV", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            DialogResult = DialogResult.OK; Close();
        }
    }

    sealed class FolderItem
    {
        internal string Id, Path;
        public override string ToString() { return Path; }
    }

    sealed class AboutDialog : Form
    {
        internal AboutDialog()
        {
            Text = "About FV"; Icon = Program.AppIcon; Font = SystemFonts.MessageBoxFont; FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false; ShowInTaskbar = false; StartPosition = FormStartPosition.CenterScreen; ClientSize = new Size(390, 220);
            Version appVersion = Assembly.GetExecutingAssembly().GetName().Version;
            string versionText = String.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}", appVersion.Major, appVersion.Minor, appVersion.Build);
            Controls.Add(new Label { Text = "FV", Font = new Font(Font.FontFamily, 15, FontStyle.Bold), AutoSize = true, Location = new Point(20, 20) });
            Controls.Add(new Label { Text = "Version " + versionText + "\r\n\r\nAuthor: Imamul Kadir\r\nCompany: PentaPet\r\n\r\nFolder access control for Windows", AutoSize = true, Location = new Point(20, 55) });
            LinkLabel link = new LinkLabel { Text = "https://imamulkadir.github.io/", AutoSize = true, Location = new Point(20, 155) };
            link.LinkClicked += delegate { System.Diagnostics.Process.Start(link.Text); }; Controls.Add(link);
            Button ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Size = new Size(82, 27), Location = new Point(290, 178) };
            Ui.StyleButton(ok, true); Controls.Add(ok); AcceptButton = ok;
        }
    }

    sealed class MainForm : Form, IMessageFilter
    {
        readonly AppConfig config; readonly string sid; readonly ListBox list; readonly Button unlock; readonly Label count; readonly Label empty;
        readonly Image rowLock;
        readonly List<Control> managementControls = new List<Control>();
        Panel authPanel; TextBox authPassword; TextBox authConfirm; Label authError; bool creatingPassword; string pendingUnlock;
        readonly Timer idleTimer;
        DateTime lastActivity;
        bool authenticated;

        internal MainForm(AppConfig config) : this(config, false, null, true) { }

        internal MainForm(AppConfig config, bool setup, string requestedFolder) : this(config, setup, requestedFolder, false) { }

        MainForm(AppConfig config, bool setup, string requestedFolder, bool skipAuthentication)
        {
            this.config = config; sid = Acl.Sid; Text = "FV"; Icon = Program.AppIcon; Font = SystemFonts.MessageBoxFont; BackColor = Ui.Canvas;
            StartPosition = FormStartPosition.Manual; MinimumSize = new Size(620, 400); ClientSize = new Size(700, 425);
            Shown += CenterOnActiveScreen;
            rowLock = SvgIcons.Load("FV.lock.svg", 17);
            Controls.Add(new Label { Text = "Locked folders", Font = new Font(Font, FontStyle.Bold), AutoSize = true, Location = new Point(18, 13) });
            count = new Label { Text = "0 folders protected", ForeColor = Ui.Muted, AutoSize = true, Location = new Point(18, 34) }; Controls.Add(count);

            ToolTip tips = new ToolTip();
            Button lockButton = new Button { Image = SvgIcons.Load("FV.lock.svg", 20), Size = new Size(40, 36), Location = new Point(596, 10), Anchor = AnchorStyles.Top | AnchorStyles.Right, AccessibleName = "Lock folder" };
            Ui.StyleIconButton(lockButton);
            tips.SetToolTip(lockButton, "Lock folder"); lockButton.Click += delegate(object sender, EventArgs e) { list.ClearSelected(); LockFolder(sender, e); }; Controls.Add(lockButton);
            unlock = new Button { Image = SvgIcons.Load("FV.unlock.svg", 20), Enabled = false, Size = new Size(40, 36), Location = new Point(642, 10), Anchor = AnchorStyles.Top | AnchorStyles.Right, AccessibleName = "Unlock selected folder" };
            Ui.StyleIconButton(unlock);
            tips.SetToolTip(unlock, "Unlock selected folder"); unlock.Click += delegate { FolderItem item = list.SelectedItem as FolderItem; if (item != null) UnlockId(item.Id); }; Controls.Add(unlock);

            list = new ListBox { Location = new Point(18, 58), Size = new Size(664, 318), Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right, HorizontalScrollbar = true, IntegralHeight = false, BorderStyle = BorderStyle.FixedSingle, BackColor = Ui.Surface, DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = 40, SelectionMode = SelectionMode.One };
            list.SelectedIndexChanged += delegate { unlock.Enabled = list.SelectedItem != null; }; list.MouseDown += DeselectBlankSpace; list.DrawItem += DrawFolderItem;
            list.DoubleClick += delegate { FolderItem item = list.SelectedItem as FolderItem; if (item != null) UnlockId(item.Id); }; Controls.Add(list);
            empty = new Label { Text = "No locked folders\r\nUse the lock button above to protect a folder.", TextAlign = ContentAlignment.MiddleCenter, ForeColor = Ui.Muted, BackColor = Ui.Surface, Location = new Point(19, 59), Size = new Size(662, 316), Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
            empty.Click += delegate { list.ClearSelected(); }; Controls.Add(empty); empty.BringToFront();

            Button change = new Button { Text = "Change password", Size = new Size(128, 30), Location = new Point(18, 390), Anchor = AnchorStyles.Bottom | AnchorStyles.Left };
            Ui.StyleButton(change, false); change.Click += delegate(object sender, EventArgs e) { list.ClearSelected(); ChangePassword(sender, e); }; Controls.Add(change);
            Button about = new Button { Text = "About", Size = new Size(76, 30), Location = new Point(154, 390), Anchor = AnchorStyles.Bottom | AnchorStyles.Left };
            Ui.StyleButton(about, false);
            about.Click += delegate { list.ClearSelected(); using (AboutDialog d = new AboutDialog()) d.ShowDialog(this); }; Controls.Add(about);
            MouseDown += delegate { list.ClearSelected(); };
            RefreshList();
            foreach (Control control in Controls) managementControls.Add(control);
            authenticated = skipAuthentication;
            if (!skipAuthentication) ShowAuthentication(setup, requestedFolder);
            lastActivity = DateTime.UtcNow;
            idleTimer = new Timer { Interval = 1000 };
            idleTimer.Tick += CheckIdle;
            idleTimer.Start();
            Application.AddMessageFilter(this);
            FormClosed += delegate
            {
                idleTimer.Stop();
                idleTimer.Dispose();
                Application.RemoveMessageFilter(this);
            };
        }

        void ShowAuthentication(bool setup, string requestedFolder)
        {
            creatingPassword = setup;
            pendingUnlock = requestedFolder;
            authConfirm = null;
            foreach (Control control in managementControls) control.Visible = false;
            authPanel = new Panel { Dock = DockStyle.Fill, BackColor = Ui.Canvas };
            Image brandImage = Program.AppIcon.ToBitmap();
            PictureBox brand = new PictureBox { Image = brandImage, SizeMode = PictureBoxSizeMode.Zoom, Location = new Point(328, 52), Size = new Size(44, 44) };
            authPanel.Controls.Add(brand);
            authPanel.Disposed += delegate { brandImage.Dispose(); };
            Label title = new Label { Text = "Folder Vault", Font = new Font(Font.FontFamily, 16, FontStyle.Bold), TextAlign = ContentAlignment.MiddleCenter, Location = new Point(110, 101), Size = new Size(480, 32) };
            authPanel.Controls.Add(title);
            int top = setup ? 148 : 154;
            string caption = setup ? "New password:" : "Master password:";
            authPanel.Controls.Add(new Label { Text = caption, AutoSize = true, Location = new Point(145, top + 4) });
            authPassword = new TextBox { Location = new Point(270, top), Size = new Size(270, 24), UseSystemPasswordChar = true };
            authPanel.Controls.Add(authPassword);
            top += 36;
            if (setup)
            {
                authPanel.Controls.Add(new Label { Text = "Confirm password:", AutoSize = true, Location = new Point(145, top + 4) });
                authConfirm = new TextBox { Location = new Point(270, top), Size = new Size(270, 24), UseSystemPasswordChar = true };
                authPanel.Controls.Add(authConfirm);
                top += 36;
            }
            CheckBox show = new CheckBox { Text = setup ? "Show passwords" : "Show password", AutoSize = true, Location = new Point(270, top + 2) };
            show.CheckedChanged += delegate
            {
                bool hidden = !show.Checked;
                authPassword.UseSystemPasswordChar = hidden;
                if (authConfirm != null) authConfirm.UseSystemPasswordChar = hidden;
            };
            authPanel.Controls.Add(show);
            string submitText = setup ? "Create password" : "Unlock";
            int submitWidth = setup ? 110 : 82;
            Button submit = new Button { Text = submitText, Size = new Size(submitWidth, 29), Location = new Point(540 - submitWidth, top + 43) };
            Ui.StyleButton(submit, true);
            submit.Click += Authenticate;
            authPanel.Controls.Add(submit);
            authError = new Label { ForeColor = Color.FromArgb(180, 35, 35), TextAlign = ContentAlignment.MiddleCenter, Location = new Point(110, top + 80), Size = new Size(480, 35) };
            authPanel.Controls.Add(authError);
            Controls.Add(authPanel);
            authPanel.BringToFront();
            AcceptButton = submit;
            if (Visible) BeginInvoke((MethodInvoker)delegate { authPassword.Focus(); });
            else Shown += delegate { authPassword.Focus(); };
        }

        void Authenticate(object sender, EventArgs e)
        {
            authError.Text = "";
            try
            {
                if (String.IsNullOrEmpty(authPassword.Text))
                    throw new ArgumentException(creatingPassword ? "Enter a new password." : "Enter your master password.");
                if (creatingPassword)
                {
                    if (authPassword.Text.Length < 8) throw new ArgumentException("Use at least 8 characters.");
                    if (authConfirm == null || authPassword.Text != authConfirm.Text) throw new ArgumentException("Passwords do not match.");
                    Passwords.Set(config, authPassword.Text);
                }
                else Passwords.Verify(config, authPassword.Text);
            }
            catch (Exception x)
            {
                authPassword.SelectAll();
                authPassword.Focus();
                authError.Text = x.Message;
                return;
            }
            AcceptButton = null;
            Controls.Remove(authPanel);
            authPanel.Dispose();
            authPanel = null;
            foreach (Control control in managementControls) control.Visible = true;
            RefreshList();
            authenticated = true;
            lastActivity = DateTime.UtcNow;
            list.Focus();
            if (!String.IsNullOrEmpty(pendingUnlock))
            {
                string target = pendingUnlock;
                pendingUnlock = null;
                BeginInvoke((MethodInvoker)delegate { UnlockRequested(target); });
            }
        }

        public bool PreFilterMessage(ref Message message)
        {
            bool keyboard = message.Msg >= 0x0100 && message.Msg <= 0x0109;
            bool mouse = message.Msg >= 0x0200 && message.Msg <= 0x020E;
            if (authenticated && (keyboard || mouse)) lastActivity = DateTime.UtcNow;
            return false;
        }

        void CheckIdle(object sender, EventArgs e)
        {
            if (authenticated && Enabled && DateTime.UtcNow.Subtract(lastActivity).TotalSeconds >= 30)
                LockAfterIdle();
        }

        void LockAfterIdle()
        {
            if (!authenticated || authPanel != null) return;
            authenticated = false;
            list.ClearSelected();
            ShowAuthentication(false, null);
        }

        internal void TriggerIdleLockForTest()
        {
            lastActivity = DateTime.UtcNow.AddSeconds(-31);
            CheckIdle(this, EventArgs.Empty);
        }

        void CenterOnActiveScreen(object sender, EventArgs e)
        {
            Rectangle area = Screen.FromPoint(Cursor.Position).WorkingArea;
            Location = new Point(area.Left + (area.Width - Width) / 2, area.Top + (area.Height - Height) / 2);
        }

        void DrawFolderItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index >= 0)
            {
                bool selected = (e.State & DrawItemState.Selected) != 0;
                using (SolidBrush background = new SolidBrush(selected ? Color.FromArgb(235, 231, 252) : Ui.Surface)) e.Graphics.FillRectangle(background, e.Bounds);
                Color color = selected ? Color.FromArgb(55, 42, 126) : Color.FromArgb(37, 37, 42);
                e.Graphics.DrawImage(rowLock, e.Bounds.X + 12, e.Bounds.Y + (e.Bounds.Height - rowLock.Height) / 2, rowLock.Width, rowLock.Height);
                Rectangle textArea = new Rectangle(e.Bounds.X + 40, e.Bounds.Y, e.Bounds.Width - 50, e.Bounds.Height);
                TextRenderer.DrawText(e.Graphics, list.Items[e.Index].ToString(), Font, textArea, color, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
                using (Pen divider = new Pen(Color.FromArgb(237, 237, 241))) e.Graphics.DrawLine(divider, e.Bounds.Left + 40, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            }
        }

        void DeselectBlankSpace(object sender, MouseEventArgs e)
        {
            int index = list.IndexFromPoint(e.Location);
            if (index == ListBox.NoMatches) list.ClearSelected();
        }

        void RefreshList()
        {
            list.Items.Clear(); foreach (KeyValuePair<string, LockedRecord> p in config.Locked) list.Items.Add(new FolderItem { Id = p.Key, Path = p.Value.Path });
            int total = list.Items.Count; count.Text = total == 1 ? "1 folder protected" : total.ToString(CultureInfo.InvariantCulture) + " folders protected";
            empty.Visible = total == 0; unlock.Enabled = false;
        }

        static string Normalize(string path) { return Path.GetFullPath(path).TrimEnd('\\'); }
        static bool Same(string a, string b) { return String.Equals(Normalize(a), Normalize(b), StringComparison.OrdinalIgnoreCase); }

        void LockFolder(object sender, EventArgs e)
        {
            using (FolderBrowserDialog picker = new FolderBrowserDialog())
            {
                picker.Description = "Select a folder to lock"; picker.ShowNewFolderButton = false;
                if (picker.ShowDialog(this) != DialogResult.OK) return;
                string folder = Normalize(picker.SelectedPath);
                string[] blocked = { Environment.GetFolderPath(Environment.SpecialFolder.Windows), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Store.DirectoryPath };
                foreach (string value in blocked) if (!String.IsNullOrEmpty(value) && Same(folder, value)) { MessageBox.Show(this, "This location is too broad or required by Windows/FV.", "Folder not allowed", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                foreach (LockedRecord record in config.Locked.Values) if (Same(record.Path, folder)) { MessageBox.Show(this, "This folder is already locked by FV.", "Already locked", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
                if (MessageBox.Show(this, folder + "\r\n\r\nFV changes only Windows permissions. No file will be moved, renamed, deleted, hidden, or encrypted.", "Lock this folder?", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                string id = Guid.NewGuid().ToString("N");
                try
                {
                    Application.DoEvents();
                    config.Locked[id] = new LockedRecord { Path = folder, OriginalSddl = Acl.Read(folder), UserSid = sid }; Store.Save(config);
                    try { Acl.Lock(folder, sid); } catch { config.Locked.Remove(id); Store.Save(config); throw; }
                    RefreshList();
                }
                catch (Exception x) { MessageBox.Show(this, x.Message + "\r\n\r\nNo files were moved, renamed, deleted, or encrypted.", "Lock failed", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            }
        }

        void UnlockId(string id)
        {
            LockedRecord record; if (!config.Locked.TryGetValue(id, out record)) return;
            try { Application.DoEvents(); Acl.Restore(record.Path, record.OriginalSddl); config.Locked.Remove(id); Store.Save(config); RefreshList(); }
            catch (Exception x) { MessageBox.Show(this, x.Message + "\r\n\r\nFV kept the original ACL so you can retry.", "Unlock failed", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        internal void UnlockRequested(string path)
        {
            foreach (KeyValuePair<string, LockedRecord> p in config.Locked) if (Same(p.Value.Path, path)) { UnlockId(p.Key); return; }
            MessageBox.Show(this, "This folder is not in FV's locked-folder list:\r\n\r\n" + path, "Folder not managed by FV", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void ChangePassword(object sender, EventArgs e)
        {
            using (PasswordDialog d = new PasswordDialog(PasswordMode.Change))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                try { Passwords.Verify(config, d.CurrentPassword); Passwords.Set(config, d.PasswordValue); MessageBox.Show(this, "Your FV master password has been updated.", "Password updated", MessageBoxButtons.OK, MessageBoxIcon.Information); }
                catch (Exception x) { MessageBox.Show(this, x.Message, "Password not changed", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            }
        }
    }

    static class ExplorerIntegration
    {
        [DllImport("shell32.dll")] static extern void SHChangeNotify(uint eventId, uint flags, IntPtr item1, IntPtr item2);
        internal static void Register()
        {
            string exe = Application.ExecutablePath; const string path = @"Software\Classes\Directory\shell\FVUnlock";
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(path)) { key.SetValue(null, "Unlock with FV"); key.SetValue("MultiSelectModel", "Single"); key.SetValue("Icon", exe); }
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(path + @"\command")) key.SetValue(null, "\"" + exe + "\" --unlock-folder \"%1\"");
            SHChangeNotify(0x08000000, 0, IntPtr.Zero, IntPtr.Zero);
        }
        internal static void RemoveStartup()
        {
            try { using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true)) { if (key != null) { key.DeleteValue("FV", false); key.DeleteValue("VaultFolder", false); } } } catch { }
        }
    }

    static class Program
    {
        [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
        internal static Icon AppIcon;

        static void SmokeTest()
        {
            using (MainForm authForm = new MainForm(new AppConfig(), false, null))
            {
                authForm.Show();
                Application.DoEvents();
                bool authVisible = false, folderListHidden = false, brandTitle = false, brandIcon = false;
                foreach (Control control in authForm.Controls)
                {
                    Panel panel = control as Panel;
                    if (panel != null && panel.Visible)
                    {
                        authVisible = true;
                        foreach (Control child in panel.Controls)
                        {
                            if (child is Label && child.Text == "Folder Vault") brandTitle = true;
                            PictureBox picture = child as PictureBox;
                            if (picture != null && picture.Image != null) brandIcon = true;
                        }
                    }
                    if (control is ListBox && !control.Visible) folderListHidden = true;
                }
                if (!authVisible || !folderListHidden || !brandTitle || !brandIcon)
                    throw new InvalidOperationException("FV did not open in its unified authentication state.");
                authForm.Close();
            }

            using (MainForm testForm = new MainForm(new AppConfig()))
            {
                testForm.Show();
                Application.DoEvents();
                Rectangle area = Screen.FromPoint(Cursor.Position).WorkingArea;
                int expectedLeft = area.Left + (area.Width - testForm.Width) / 2;
                int expectedTop = area.Top + (area.Height - testForm.Height) / 2;
                if (Math.Abs(testForm.Left - expectedLeft) > 2 || Math.Abs(testForm.Top - expectedTop) > 2)
                    throw new InvalidOperationException("FV did not open in the center of the active screen.");
                testForm.TriggerIdleLockForTest();
                Application.DoEvents();
                bool relocked = false;
                foreach (Control control in testForm.Controls)
                    if (control is Panel && control.Visible) relocked = true;
                if (!relocked) throw new InvalidOperationException("FV did not relock after inactivity.");
                testForm.Close();
            }

            AppConfig populated = new AppConfig();
            populated.Locked["preview"] = new LockedRecord { Path = @"C:\Preview\Protected folder", OriginalSddl = "", UserSid = Acl.Sid };
            using (MainForm populatedForm = new MainForm(populated))
            {
                populatedForm.Show();
                Application.DoEvents();
                ListBox previewList = null;
                int imageButtons = 0;
                foreach (Control control in populatedForm.Controls)
                {
                    if (control is ListBox) previewList = (ListBox)control;
                    Button button = control as Button;
                    if (button != null && button.Image != null) imageButtons++;
                }
                if (imageButtons != 2) throw new InvalidOperationException("FV did not render both folder action icons.");
                if (previewList == null || previewList.Items.Count != 1) throw new InvalidOperationException("FV did not render the protected-folder list.");
                previewList.SelectedIndex = 0;
                MethodInfo mouseDown = typeof(Control).GetMethod("OnMouseDown", BindingFlags.Instance | BindingFlags.NonPublic);
                mouseDown.Invoke(previewList, new object[] { new MouseEventArgs(MouseButtons.Left, 1, 20, 20, 0) });
                Application.DoEvents();
                if (previewList.SelectedIndex != 0) throw new InvalidOperationException("FV cleared a folder during its selection click.");
                populatedForm.Close();
            }

            string testPath = Path.Combine(Path.GetTempPath(), "fv-acl-smoke-" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(testPath);
            string originalSddl = null;
            try
            {
                originalSddl = Acl.Read(testPath);
                Acl.Lock(testPath, Acl.Sid);
                Acl.Restore(testPath, originalSddl);
            }
            finally
            {
                if (originalSddl != null)
                {
                    try { Acl.Restore(testPath, originalSddl); } catch { }
                }
                if (System.IO.Directory.Exists(testPath)) System.IO.Directory.Delete(testPath);
            }
        }

        [STAThread]
        static void Main(string[] args)
        {
            SetProcessDPIAware(); Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false); AppIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            foreach (string argument in args)
            {
                if (argument == "--smoke-test")
                {
                    SmokeTest();
                    return;
                }
            }
            ExplorerIntegration.RemoveStartup();
            try { ExplorerIntegration.Register(); } catch (Exception x) { MessageBox.Show("FV could not register the Explorer command.\r\n\r\n" + x.Message, "Explorer integration unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            AppConfig config;
            try { config = Store.Load(); } catch (Exception x) { MessageBox.Show(x.Message, "FV configuration error", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
            bool setup = !Passwords.Current(config);
            string request = null; for (int i = 0; i < args.Length - 1; i++) if (args[i] == "--unlock-folder") { request = args[i + 1]; break; }
            Application.Run(new MainForm(config, setup, request));
        }
    }
}
