using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace Antivirus
{
    /// <summary>
    /// Interaction logic for ScanFile.xaml
    /// </summary>
    public partial class ScanFile : Window
    {
        private string file;
        private Dictionary<string, string> signatures;
        private Thread scanFileThread;
        private bool readyToScan = true;
        private FileMalware fileMalwareDialog;
        private static readonly string DangerousFile = "File {0} contains dangerous code:\n{1}. Hazard type: {2}";
        private static readonly string HashsumChange = "Hashsum of file {0} was changed.\n Previous hashsum: {1} was formed {2}.\nNew value: {3}";
        public ScanFile()
        {
            InitializeComponent();
            var desktopWorkingArea = SystemParameters.WorkArea;
            this.Left = desktopWorkingArea.Right - this.Width;
            this.Top = desktopWorkingArea.Bottom - this.Height;
        }

        private void buttonScan_Click(object sender, RoutedEventArgs e)
        {
            if (readyToScan)
            {
                if (File.Exists(textBoxPath.Text))
                {
                    readyToScan = false;
                    scanFileThread = new Thread(new ThreadStart(StartScan));
                    scanFileThread.Start();
                    buttonScan.Content = "Stop scanning";
                }
                else
                {
                    MessageBox.Show("Given file does not exist.", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else
            {
                scanFileThread.Abort();
            }
        }

        public void StartScan()
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                file = textBoxPath.Text;
                signatures = new Dictionary<string, string>();

                signatures = signatures.Union(Signatures.GetLocalSignatures()).ToDictionary(x => x.Key, x => x.Value);
            });

            if (!DbWorker.IsProcessInTrustedProcesses(file))
            {
                try
                {
                    bool isDetected = false;
                    var allLines = File.ReadAllLines(file);
                    var beforeScanning = DateTime.Now;
                    Parallel.ForEach(allLines, line =>
                    {
                        foreach (KeyValuePair<string, string> kvp in signatures)
                        {
                            if (line.Contains(kvp.Key))
                            {
                                string text = string.Format(DangerousFile, file, kvp.Key, kvp.Value);
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    isDetected = true;
                                    fileMalwareDialog = new FileMalware(file, text);
                                    fileMalwareDialog.ShowDialog();
                                });


                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    if (fileMalwareDialog.MalwareAction == MalwareActions.Abort)
                                    {
                                        readyToScan = true;
                                        scanFileThread.Abort();
                                    }
                                });
                            }
                        }
                    });

                    if (!isDetected)
                    {
                        MessageBox.Show("File is not dangerous!", "All clear!", MessageBoxButton.OK, MessageBoxImage.Information);
                    }

                    isDetected = false;
                    bool isHash = false;
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        isHash = checkBoxAllowHash.IsChecked.GetValueOrDefault();
                    });
                    if (isHash)
                    {
                        FileChecksum fileMD5 = new FileChecksum(file);
                        if (DbWorker.IsProcessInProcessesMD5(fileMD5.MainFilePath))
                        {
                            if (!DbWorker.CompareProcessesMD5(fileMD5.MainFilePath, fileMD5.Md5))
                            {
                                isDetected = true;
                                FileChecksum oldMD5 = DbWorker.GetProcessMD5(fileMD5.MainFilePath);
                                string text = string.Format(HashsumChange, file, oldMD5.Md5, oldMD5.Date.ToString(), fileMD5.Md5);

                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    HashDetected hashDetectedDialog = new HashDetected(null, fileMD5, text);
                                    hashDetectedDialog.ShowDialog();

                                    if (hashDetectedDialog.MalwareAction == MalwareActions.Abort)
                                    {
                                        readyToScan = true;
                                        scanFileThread.Abort();
                                    }
                                });
                            }
                        }
                        else
                        {
                            DbWorker.InsertProcessMD5(fileMD5);
                            MessageBox.Show("Hashsum has been added to DB!", "All clear!", MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                    }
                    MessageBox.Show("Scan finished.", "Scan finished!", MessageBoxButton.OK, MessageBoxImage.Information);
                    readyToScan = true;
                }
                catch { };
            }
            Application.Current.Dispatcher.Invoke(() =>
            {
                buttonScan.Content = "Start scanning";
            });
        }

        private void buttonChoose_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dialog = new Microsoft.Win32.OpenFileDialog();
            Nullable<bool> result = dialog.ShowDialog();
            if (result == true)
            {
                textBoxPath.Text = dialog.FileName;
            }
        }
    }
}
