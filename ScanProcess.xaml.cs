using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows;

namespace Antivirus
{
    public partial class ScanProcess : Window
    {
        private Dictionary<string, string> signatures;
        private List<string> files;
        Thread scanThread;
        private FileMalware fileMalwareDialog;
        private HashDetected hashDetectedDialog;

        private static readonly string DangerousFile = "File {0} contains dangerous code:\n{1}. Hazard type: {2}";
        private static readonly string HashsumChange = "Hashsum of file {0} was changed.\n Previous hashsum: {1} was formed {2}.\nNew value: {3}";

        public ScanProcess()
        {
            ResizeMode = ResizeMode.NoResize;
            InitializeComponent();
        }

        private void buttonChoose_Click(object sender, RoutedEventArgs e)
        {
            using (var dialog = new System.Windows.Forms.FolderBrowserDialog())
            {
                System.Windows.Forms.DialogResult result = dialog.ShowDialog();
                textBoxPath.Text = dialog.SelectedPath;
            }
        }

        private void buttonScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                files = new List<string>(Directory.GetFiles(textBoxPath.Text, "*.*", SearchOption.AllDirectories)
                    .Where(s =>
                    s.EndsWith(".exe") ||
                    s.EndsWith(".ini") ||
                    s.EndsWith(".bat") ||
                    s.EndsWith(".dll") ||
                    s.EndsWith(".mp3") ||
                    s.EndsWith(".jpg")));
                if (!files.Any())
                {
                    MessageBox.Show("Selected directory is empty!", "Empty!", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    panelChoose.Visibility = Visibility.Hidden;
                    panelScan.Visibility = Visibility.Visible;
                    this.Height = 378;
                    scanThread = new Thread(new ThreadStart(StartScan));
                    scanThread.Start();
                }
            }
            catch (Exception exc)
            {
                MessageBox.Show($"Wrong path! {exc.Message}", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public void StartScan()
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                textBlockLog.Text += $"Started scanning: {textBoxPath.Text}";
                signatures = Signatures.GetLocalSignatures();
                progressBar.Maximum = files.Count();
                progressBar.Minimum = 0;
            });

            foreach (string file in files)
            {
                if (!DbWorker.IsProcessInTrustedProcesses(file))
                {
                    try
                    {
                        if (file.EndsWith(".exe"))
                        {
                            string fileString = Encoding.UTF8.GetString(File.ReadAllBytes(file));
                            foreach (KeyValuePair<string, string> kvp in signatures)
                            {
                                if (fileString.Contains(kvp.Key))
                                {
                                    string text = string.Format(DangerousFile, file, kvp.Key, kvp.Value);
                                    Application.Current.Dispatcher.Invoke(() =>
                                    {
                                        textBlockLog.Text += "\n" + text;
                                    });

                                    fileMalwareDialog = new FileMalware(file, text);
                                    fileMalwareDialog.ShowDialog();

                                    Application.Current.Dispatcher.Invoke(() =>
                                    {
                                        if (fileMalwareDialog.MalwareAction == MalwareActions.Trust)
                                        {
                                            textBlockLog.Text += "\nFile was added to exceptions.";
                                        }
                                        else if (fileMalwareDialog.MalwareAction == MalwareActions.Abort)
                                        {
                                            textBlockLog.Text += "\nScanning was aborted.";
                                            scanThread.Abort();
                                        }
                                        else if (fileMalwareDialog.MalwareAction == MalwareActions.Skip)
                                        {
                                            textBlockLog.Text += "\nFile is skipped, scanning will now resume.";
                                        }
                                        else if (fileMalwareDialog.MalwareAction == MalwareActions.Delete)
                                        {
                                            textBlockLog.Text += "\nFile was deleted.";
                                        }
                                        else if (fileMalwareDialog.MalwareAction == MalwareActions.Kill)
                                        {
                                            textBlockLog.Text += "\nFile was deleted and all associated processes were shut down.";
                                        }
                                    });
                                }
                                else
                                {
                                    Application.Current.Dispatcher.Invoke(() =>
                                    {
                                        textBlockLog.Text += $"\nFile {file} does not contain any dangerous code.";
                                    });
                                }
                            }
                        }

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
                                    FileChecksum oldMD5 = DbWorker.GetProcessMD5(fileMD5.MainFilePath);
                                    string text = string.Format(HashsumChange, file, oldMD5.Md5, oldMD5.Date.ToString(), fileMD5.Md5);
                                    Application.Current.Dispatcher.Invoke(() =>
                                    {
                                        textBlockLog.Text += $"\n{text}";
                                        hashDetectedDialog = new HashDetected(null, fileMD5, text);
                                        hashDetectedDialog.ShowDialog();
                                    });

                                    Application.Current.Dispatcher.Invoke(() =>
                                    {
                                        if (hashDetectedDialog.MalwareAction == MalwareActions.Abort)
                                        {
                                            textBlockLog.Text += "\nScanning aborted.";
                                            scanThread.Abort();
                                        }
                                        else if (hashDetectedDialog.MalwareAction == MalwareActions.Skip)
                                        {
                                            textBlockLog.Text += "\nFile was skipped, scanning will now resume.";
                                        }
                                        else if (hashDetectedDialog.MalwareAction == MalwareActions.Delete)
                                        {
                                            textBlockLog.Text += "\nFile's checksum was updated.";
                                        }
                                        else if (hashDetectedDialog.MalwareAction == MalwareActions.Kill)
                                        {
                                            textBlockLog.Text += "\nFile was deleted and associated processes were shut down.";
                                        }
                                        else if (hashDetectedDialog.MalwareAction == MalwareActions.Trust)
                                        {
                                            textBlockLog.Text += "\nFile was added to exclusions.";
                                        }
                                    });
                                }
                            }
                            else
                            {
                                DbWorker.InsertProcessMD5(fileMD5);
                            }
                        }
                    }
                    catch { };
                }
                Application.Current.Dispatcher.Invoke(() =>
                {
                    progressBar.Value++;
                });
            }
            Application.Current.Dispatcher.Invoke(() =>
            {
                textBlockLog.Text += "\nScanning finished.";
                buttonFinish.Content = "End";
            });
        }

        private void buttonFinish_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                scanThread.Abort();
            }
            catch { };
            Close();
        }
    }
}
