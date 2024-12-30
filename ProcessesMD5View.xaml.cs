using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;

namespace Antivirus
{
    public partial class ProcessesMD5View : Window
    {
        public ProcessesMD5View()
        {
            InitializeComponent();
            listView.Items.Clear();
            List<FileChecksum> processesMD5 = DbWorker.GetProcessesMD5();
            foreach (FileChecksum processMD5 in processesMD5)
            {
                listView.Items.Add(processMD5);
            }
        }

        private void buttonBack_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void listView_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Delete)
            {
                DeleteItem();
            }
        }

        private void contextItemDelete_Click(object sender, RoutedEventArgs e)
        {
            DeleteItem();
        }

        private void contextItemClear_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (MessageBox.Show("Do you really want to delete all entries?", "Confirmation",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    DbWorker.ClearProcessesMD5();
                    listView.Items.Clear();
                }
            }
            catch { };
        }

        private void contextItemAdd_Click(object sender, RoutedEventArgs e)
        {
            new AddMD5(this).ShowDialog();
        }


        private void DeleteItem()
        {
            try
            {
                if (MessageBox.Show("Delete checksum for selected file?", "Confirmation",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    FileChecksum fileMD5 = listView.SelectedItem as FileChecksum;
                    DbWorker.DeleteProcessMD5(fileMD5.MainFilePath);
                    listView.Items.Remove(fileMD5);
                }
            }
            catch { };
        }
    }
}
