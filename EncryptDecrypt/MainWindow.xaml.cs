using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using PropertyChanged;

namespace EncryptDecrypt
{
    /// <summary>
    ///     Interaktionslogik für MainWindow.xaml
    /// </summary>
    [AddINotifyPropertyChangedInterface]
    public partial class MainWindow
    {
        private string _input;
        private string _crypted;

        public MainWindow()
        {
            InitializeComponent();
            DataContext = this;
            EncryptionKey = "randomText123";
        }

        public static string EncryptionKey { get; set; }
        
        public string Input
        {
            get => _input;
            set
            {
                _input = value;
                Crypted = Encrypt(_input);
            }
        }

        public string Crypted
        {
            get => _crypted;
            set
            {
                _crypted = value;
                Decrypted = Decrypt(_crypted);
            }
        }

        public string Decrypted { get; set; }

        public static string Encrypt(string clearText)
        {
            var encryptionKey = EncryptionKey;
            var clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (var encryptor = Aes.Create())
            {
                var pdb = new Rfc2898DeriveBytes(encryptionKey,
                    new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }

                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }

            return clearText;
        }

        public static string Decrypt(string cipherText)
        {
            var encryptionKey = EncryptionKey;
            cipherText = cipherText.Replace(" ", "+");
            var cipherBytes = Convert.FromBase64String(cipherText);
            using (var encryptor = Aes.Create())
            {
                var pdb = new Rfc2898DeriveBytes(encryptionKey,
                    new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }

                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }

            return cipherText;
        }
    }
}