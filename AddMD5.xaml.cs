using System;
using System.IO;
using System.Windows;

namespace Antivirus
{
    public partial class AddMD5 : Window
    {
        private ProcessesMD5View root;
        public AddMD5(ProcessesMD5View root)
        {
            this.root = root;
            InitializeComponent();
        }

        private void buttonAdd_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBox.Text))
            {
                FileChecksum fileMD5 = new FileChecksum(textBox.Text);
                DbWorker.InsertProcessMD5(fileMD5);
                root.listView.Items.Add(fileMD5);
                Close();
            }
            else
            {
                MessageBox.Show("Given file does not exist!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void buttonChoose_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            bool? result = dialog.ShowDialog();
            if (result == true)
            {
                textBox.Text = dialog.FileName;
            }
        }
    }
}