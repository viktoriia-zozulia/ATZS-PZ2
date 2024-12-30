using System.Collections.Generic;

namespace Antivirus
{
    static class Signatures
    {
        private static Dictionary<string, string> signatures = new Dictionary<string, string>();

        static Signatures()
        {
            signatures.Add("CreateRemoteThread", "Trojan");
            signatures.Add("GetAsyncKeyState", "Trojan");
            signatures.Add("GetForegroundWindow", "Keylogger");
            signatures.Add("GetWindowText", "Keylogger");
            signatures.Add("JOIN", "Trojan");
            signatures.Add("MD5CryptoServiceProvider", "Crypter");
            signatures.Add("NtUnmapViewOfSection", "Trojan");
            signatures.Add("PRIVMSG", "Trojan");
            signatures.Add("RijndaelManaged", "Crypter");
            signatures.Add("SetWindowsHookEx", "Keylogger");
            signatures.Add(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "Virus");
            signatures.Add(@"NURE is virus", "Virus");
        }

        public static Dictionary<string, string> GetLocalSignatures()
        {
            return signatures;
        }
    }
}
