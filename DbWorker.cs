using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Windows;

namespace Antivirus
{
    static class DbWorker
    {
        private static readonly string DbName = "signatures.db";
        private static readonly string connectionString = $"Data Source={DbName};Version=3;";

        static DbWorker()
        {
            if (!File.Exists(DbName))
            {
                SQLiteConnection.CreateFile(DbName);
            }
            string createTable = @"
                CREATE TABLE IF NOT EXISTS TrustedProcesses (
                    ProcessMainFilePath varchar
                );

                CREATE TABLE IF NOT EXISTS ProcessesMD5 (
                    ProcessMainFilePath varchar,
                    MD5 varchar,
                    Date datetime
                );
            ";

            using (var connection = new SQLiteConnection(connectionString))
            {
                connection.Open();
                using (var command = new SQLiteCommand(createTable, connection))
                {
                    command.ExecuteNonQuery();
                }
            }
        }

        public static void InsertTrustedProcess(string processMainFilePath)
        {
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "INSERT INTO TrustedProcesses (ProcessMainFilePath) VALUES (@ProcessMainFilePath)";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@ProcessMainFilePath", processMainFilePath);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch
            {
                MessageBox.Show("Given process cannot be added to the exceptions list!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public static List<string> GetTrustedProcesses()
        {
            List<string> result = new List<string>();
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "SELECT * FROM TrustedProcesses;";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        using (var dbReader = command.ExecuteReader())
                        {
                            while (dbReader.Read())
                            {
                                result.Add(dbReader["ProcessMainFilePath"].ToString());
                            }
                        }
                    }
                }
            }
            catch
            {
                MessageBox.Show("Cannot get list of trusted processes!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return result;
        }

        public static void DeleteTrustedProcess(string processMainFilePath)
        {
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "DELETE FROM TrustedProcesses WHERE ProcessMainFilePath = @ProcessMainFilePath";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@ProcessMainFilePath", processMainFilePath);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch
            {
                MessageBox.Show("Given process cannot be deleted from trusted processes list!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public static void ClearTrustedProcesses()
        {
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "DELETE FROM TrustedProcesses;";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch
            {
                MessageBox.Show("Trusted processes list cannot be cleared!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public static bool IsProcessInTrustedProcesses(string processMainFilePath)
        {
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "SELECT COUNT(*) FROM TrustedProcesses WHERE ProcessMainFilePath = @ProcessMainFilePath";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@ProcessMainFilePath", processMainFilePath);
                        int count = Convert.ToInt32(command.ExecuteScalar().ToString());
                        if (count == 0) return false; else return true;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool IsProcessInProcessesMD5(string processMainFilePath)
        {
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "SELECT COUNT(*) FROM ProcessesMD5 WHERE ProcessMainFilePath = @ProcessMainFilePath";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@ProcessMainFilePath", processMainFilePath);
                        int count = Convert.ToInt32(command.ExecuteScalar().ToString());
                        if (count == 0) return false; else return true;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool CompareProcessesMD5(string processMainFilePath, string newMD5)
        {
            bool buffer = false;
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "SELECT * FROM ProcessesMD5 WHERE ProcessMainFilePath = @ProcessMainFilePath";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@ProcessMainFilePath", processMainFilePath);
                        using (var dbReader = command.ExecuteReader())
                        {
                            while (dbReader.Read())
                            {
                                if (dbReader["MD5"].ToString().Equals(newMD5))
                                {
                                    buffer = true;
                                }
                                else
                                {
                                    buffer = false;
                                }
                            }
                        }
                    }
                    return buffer;
                }
            }
            catch
            {
                return false;
            }
        }

        public static void InsertProcessMD5(FileChecksum fileMD5)
        {
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "INSERT INTO ProcessesMD5 (ProcessMainFilePath, MD5, Date) VALUES (@ProcessMainFilePath, @MD5, @Date)";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@ProcessMainFilePath", fileMD5.MainFilePath);
                        command.Parameters.AddWithValue("@MD5", fileMD5.Md5);
                        command.Parameters.AddWithValue("@Date", fileMD5.Date);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
                MessageBox.Show("Hashsum of the process cannot be added to DB!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public static void DeleteProcessMD5(string processMainFilePath)
        {
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "DELETE FROM ProcessesMD5 WHERE ProcessMainFilePath = @ProcessMainFilePath";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@ProcessMainFilePath", processMainFilePath);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch
            {
                MessageBox.Show("Hashsum of the process cannot be deleted from DB!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public static void ClearProcessesMD5()
        {
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "DELETE FROM ProcessesMD5;";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch
            {
                MessageBox.Show("Hashsum list cannot be cleared!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public static void UpdateProcessMD5(FileChecksum fileMD5)
        {
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "UPDATE ProcessesMD5 SET MD5 = @md5, Date=@Date WHERE ProcessMainFilePath = @ProcessMainFilePath;";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@ProcessMainFilePath", fileMD5.MainFilePath);
                        command.Parameters.AddWithValue("@md5", fileMD5.Md5);
                        command.Parameters.AddWithValue("@Date", fileMD5.Date);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch
            {
                MessageBox.Show("Hashsum of the given file cannot be updated!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public static List<FileChecksum> GetProcessesMD5()
        {
            List<FileChecksum> result = new List<FileChecksum>();
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "SELECT * FROM ProcessesMD5;";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                result.Add(new FileChecksum(
                                    reader["ProcessMainFilePath"].ToString(),
                                    reader["MD5"].ToString(),
                                    DateTime.Parse(reader["Date"].ToString())));
                            }
                        }
                    }
                }
            }
            catch
            {
                MessageBox.Show("Cannot retrieve hashums from db!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return result;
        }

        public static FileChecksum GetProcessMD5(string processMainFilePath)
        {
            FileChecksum result = new FileChecksum();
            try
            {
                using (var connection = new SQLiteConnection(connectionString))
                {
                    connection.Open();
                    string query = "SELECT * FROM ProcessesMD5 WHERE ProcessMainFilePath = @ProcessMainFilePath;";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@ProcessMainFilePath", processMainFilePath);
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                result.MainFilePath = reader["ProcessMainFilePath"].ToString();
                                result.Md5 = reader["MD5"].ToString();
                                result.Date = DateTime.Parse(reader["Date"].ToString());
                            }
                        }
                    }
                }
            }
            catch
            {
                MessageBox.Show("Cannot retireve hashums from DB!", "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return result;
        }
    }
}
