using System;
using System.Diagnostics;
using System.IO;
using System.Windows;

namespace Antivirus
{
    public partial class HashDetected : Window
    {
        public MalwareActions MalwareAction { get; set; }
        private Process process;
        private FileChecksum fileMD5;

        public HashDetected(Process process, FileChecksum fileMD5, string text)
        {
            InitializeComponent();
            textBlock.Text = text;
            this.process = process;
            this.fileMD5 = fileMD5;
            MalwareAction = MalwareActions.Skip;
        }

        private void buttonSkip_Click(object sender, RoutedEventArgs e)
        {
            MalwareAction = MalwareActions.Skip;
            Close();
        }

        private void buttonAbort_Click(object sender, RoutedEventArgs e)
        {
            MalwareAction = MalwareActions.Abort;
            Close();
        }

        private void buttonTrust_Click(object sender, RoutedEventArgs e)
        {
            MalwareAction = MalwareActions.Trust;
            if(process!=null)
            {
                DbWorker.InsertTrustedProcess(process.MainModule.FileName);
            }
            else
            {
                DbWorker.InsertTrustedProcess(fileMD5.MainFilePath);
            }            
            Close();
        }

        private void buttonKill_Click(object sender, RoutedEventArgs e)
        {
            MalwareAction = MalwareActions.Kill;
            try
            {
                if (process != null)
                {
                    process.Kill();
                }
                else
                {
                    string processName = fileMD5.MainFilePath.Substring(fileMD5.MainFilePath.LastIndexOf('\\'));
                    Process[] processes = Process.GetProcessesByName(processName);
                    foreach(Process process in processes)
                    {
                        process.Kill();
                    }
                }
                File.Delete(fileMD5.MainFilePath);
                DbWorker.DeleteProcessMD5(fileMD5.MainFilePath);
            }
            catch (Exception exc)
            {
                MessageBox.Show($"Given file cannot be deleted, or it's processes cannot be stopped! {exc.Message}", "Error!", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            Close();
        }

        private void buttonUpdate_Click(object sender, RoutedEventArgs e)
        {
            MalwareAction = MalwareActions.Delete;
            DbWorker.UpdateProcessMD5(fileMD5);
            Close();
        }
    }
}
