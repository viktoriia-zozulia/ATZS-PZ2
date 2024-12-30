using System.Diagnostics;
using System.IO;
using System.Windows;

namespace Antivirus
{
    public partial class VirusDetected : Window
    {
        public MalwareActions MalwareAction { get; set; }
        private Process process;
        
        public VirusDetected(Process process, string text)
        {
            InitializeComponent();
            textBlock.Text = text;
            this.process = process;
            MalwareAction = MalwareActions.Skip;
            var desktopWorkingArea = SystemParameters.WorkArea;
            this.Left = desktopWorkingArea.Right - this.Width;
            this.Top = desktopWorkingArea.Bottom - this.Height;
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

        private void buttonDelete_Click(object sender, RoutedEventArgs e)
        {
            MalwareAction = MalwareActions.Delete;
            try
            {
                process.Kill();
                File.Delete(process.MainModule.FileName);
            }
            catch
            {
                MessageBox.Show("Given file cannot be deleted or it's process stopped.", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            Close();
        }

        private void buttonKill_Click(object sender, RoutedEventArgs e)
        {
            MalwareAction = MalwareActions.Kill;
            try
            {
                process.Kill();
            }
            catch
            {
                MessageBox.Show("Given process cannot be stopped.", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            Close();
        }

        private void buttonTrust_Click(object sender, RoutedEventArgs e)
        {
            MalwareAction = MalwareActions.Trust;
            DbWorker.InsertTrustedProcess(process.MainModule.FileName);
            Close();
        }
    }
}
