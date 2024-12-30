using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows;
using System.Threading.Tasks;
using System.Windows.Media;

namespace Antivirus
{

    public partial class MainWindow : Window
    {
        private Dictionary<string, string> signatures;
        private ManagementEventWatcher startWatch;
        private bool isRealTimeProtectionEnabled = false;
        private VirusDetected virusDetectedDialog;
        private HashDetected hashDetectedDialog;
        private Thread realTimeProtectionThread;

        private static readonly string DangerousFile = "Module {0} of process {1} contains dangerous code:\n{2}. Hazard type: {3}";
        private static readonly string HashsumChange = "Hashsum of main module {0} of process {1} was changed.\n Previous hashsum: {2} was formed {3}.\nNew value: {4}";

        private static bool isButtonEnabled = false;
        private static readonly string EnableProtection = "Enable Protection";
        private static readonly string TurnoffProtection = "Turn off Protection";

        public MainWindow()
        {
            signatures = Signatures.GetLocalSignatures();
            InitializeComponent();
        }

        private void RealTimeProtection()
        {
            foreach (Process p in Process.GetProcesses())
            {
                try
                {
                    CheckProcess(p);
                }
                catch { };
            }

            startWatch = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            startWatch.EventArrived += new EventArrivedEventHandler(startWatch_EventArrived);
            startWatch.Start();
        }

        private void startWatch_EventArrived(object sender, EventArrivedEventArgs e)
        {
            try
            {
                Process p = Process.GetProcessById(Convert.ToInt32(e.NewEvent.Properties["ProcessId"].Value));
                CheckProcess(p);
            }
            catch { };
        }

        private void CheckProcess(Process process)
        {
            if (!DbWorker.IsProcessInTrustedProcesses(process.MainModule.FileName))
            {
                try
                {
                    string fileString = Encoding.UTF8.GetString(File.ReadAllBytes(process.MainModule.FileName));
                    var allLines = File.ReadAllLines(process.MainModule.FileName);
                    Parallel.ForEach(allLines, line =>
                    {
                        foreach (KeyValuePair<string, string> kvp in signatures)
                        {
                            if (line.Contains(kvp.Key))
                            {
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    string text = string.Format(DangerousFile, process.MainModule.FileName, process.ProcessName, kvp.Key, kvp.Value);
                                    virusDetectedDialog = new VirusDetected(process, text);
                                    virusDetectedDialog.ShowDialog();
                                });

                                if (virusDetectedDialog.MalwareAction == MalwareActions.Abort)
                                {
                                    try
                                    {
                                        startWatch.Stop();
                                    }
                                    catch { };
                                    isRealTimeProtectionEnabled = false;
                                    Application.Current.Dispatcher.Invoke(() =>
                                    {
                                        ToggleEnableButtonState();
                                    });
                                    realTimeProtectionThread.Abort();
                                }
                                else if (virusDetectedDialog.MalwareAction == MalwareActions.Delete
                                    || virusDetectedDialog.MalwareAction == MalwareActions.Kill
                                    || virusDetectedDialog.MalwareAction == MalwareActions.Trust)
                                {
                                    break;
                                }
                                else if (virusDetectedDialog.MalwareAction == MalwareActions.Skip)
                                {
                                }
                            }
                        }
                    });

                    FileChecksum fileMD5 = new FileChecksum(process.MainModule.FileName);
                    if (DbWorker.IsProcessInProcessesMD5(fileMD5.MainFilePath))
                    {
                        if (!DbWorker.CompareProcessesMD5(fileMD5.MainFilePath, fileMD5.Md5))
                        {
                            Application.Current.Dispatcher.Invoke(delegate
                            {
                                FileChecksum oldMD5 = DbWorker.GetProcessMD5(fileMD5.MainFilePath);
                                string text = string.Format(HashsumChange, process.MainModule.FileName, process.ProcessName, oldMD5.Md5, oldMD5.Date.ToString(), fileMD5.Md5);
                                hashDetectedDialog = new HashDetected(process, fileMD5, text);
                                hashDetectedDialog.ShowDialog();
                            });


                            if (hashDetectedDialog.MalwareAction == MalwareActions.Abort)
                            {
                                try
                                {
                                    startWatch.Stop();
                                }
                                catch { };
                                isRealTimeProtectionEnabled = false;
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    ToggleEnableButtonState();
                                });
                                realTimeProtectionThread.Abort();
                            }
                            else
                            {
                            }
                        }
                    }
                    else
                    {
                        DbWorker.InsertProcessMD5(fileMD5);
                    }
                }
                catch { };
            }
        }

        private void buttonProtect_Click(object sender, RoutedEventArgs e)
        {
            if (!isRealTimeProtectionEnabled)
            {
                isRealTimeProtectionEnabled = true;
                ToggleEnableButtonState();
                realTimeProtectionThread = new Thread(new ThreadStart(RealTimeProtection));
                realTimeProtectionThread.Start();
            }
            else
            {
                try
                {
                    startWatch.Stop();
                }
                catch { };
                realTimeProtectionThread.Abort();
                isRealTimeProtectionEnabled = false;
                ToggleEnableButtonState();
            }
        }

        private void buttonScanFile_Click(object sender, RoutedEventArgs e)
        {
            ScanFile scanFile = new ScanFile();
            scanFile.Show();
        }

        private void buttonScanDirectory_Click(object sender, RoutedEventArgs e)
        {
            ScanProcess scanProcess = new ScanProcess();
            scanProcess.Show();
        }

        private void buttonSettings_Click(object sender, RoutedEventArgs e)
        {
            stackPanelMain.Visibility = Visibility.Hidden;
            stackPanelSettings.Visibility = Visibility.Visible;
        }

        private void buttonBack_Click(object sender, RoutedEventArgs e)
        {
            stackPanelSettings.Visibility = Visibility.Hidden;
            stackPanelMain.Visibility = Visibility.Visible;
        }

        private void buttonShowTrustedProcesses_Click(object sender, RoutedEventArgs e)
        {
            TrustedProcessesView trustedProcessesView = new TrustedProcessesView();
            trustedProcessesView.Show();
        }

        private void buttonMD5List_Click(object sender, RoutedEventArgs e)
        {
            ProcessesMD5View processesMD5View = new ProcessesMD5View();
            processesMD5View.Show();
        }

        private void ToggleEnableButtonState()
        {
            if (isButtonEnabled)
            {
                buttonProtect.Content = EnableProtection;
                buttonProtect.Background = Brushes.Green;
            }
            else
            {
                buttonProtect.Content = TurnoffProtection;
                buttonProtect.Background = Brushes.Red;
            }
            isButtonEnabled = !isButtonEnabled;
        }
    }
}
