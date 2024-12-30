using System;
using System.IO;
using System.Security.Cryptography;

namespace Antivirus
{
    public class FileChecksum
    {
        private string mainFilePath;
        private string md5;
        private DateTime dateTime;

        public FileChecksum(string mainFilePath)
        {
            this.mainFilePath = mainFilePath;
            using (var md5Checksum = MD5.Create())
            {
                using (var stream = File.OpenRead(mainFilePath))
                {
                    md5 = BitConverter.ToString(md5Checksum.ComputeHash(stream)).Replace("-", "");
                }
            }
            dateTime = DateTime.Now;
        }

        public FileChecksum(string mainFilePath, string md5, DateTime dateTime)
        {
            this.mainFilePath = mainFilePath;
            this.md5 = md5;
            this.dateTime = dateTime;
        }

        public FileChecksum() { }

        public string MainFilePath
        {
            get => mainFilePath;
            set => mainFilePath = value;
        }

        public string Md5
        {
            get => md5;
            set => md5 = value;
        }

        public DateTime Date
        {
            get => dateTime;
            set => dateTime = value;
        }
    }
}
