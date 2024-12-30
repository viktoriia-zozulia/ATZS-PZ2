using System;
using System.IO;
using System.Windows;

namespace Antivirus
{
    public partial class AddTrustedProcess : Window
    {
        private TrustedProcessesView root;
        public AddTrustedProcess(TrustedProcessesView root)
        {
            this.root = root;
            InitializeComponent();
            var desktopWorkingArea = SystemParameters.WorkArea;
            this.Left = desktopWorkingArea.Right - this.Width;
            this.Top = desktopWorkingArea.Bottom - this.Height;
        }

        private void buttonAdd_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBox.Text))
            {
                DbWorker.InsertTrustedProcess(textBox.Text);
                root.listView.Items.Add(new BindingsWorker { MainFilePath = textBox.Text });
                Close();
            }
            else
            {
                MessageBox.Show("Given file does not exist!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void buttonChoose_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dialog = new Microsoft.Win32.OpenFileDialog();
            Nullable<bool> result = dialog.ShowDialog(); 
            if (result == true)
            {
                textBox.Text = dialog.FileName;
            }
        }
    }
}
