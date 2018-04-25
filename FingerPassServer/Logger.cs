using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace FingerPassServer
{
    class Logger:IDisposable
    {
        bool disposed = false;
        SafeHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        
        protected virtual void Dispose(bool disposing)
        {
            if (disposed)
                return;

            if (disposing)
            {
                handle.Dispose();
            }

            if(file!=null)file.Close();
            disposed = true;
        }

        static bool fileWrite;
        static FileStream file;
        static int logLevel = 0;

        public static bool FileWrite { get => fileWrite; set => fileWrite = value; }
        public static int LogLevel { get => logLevel; set => logLevel = value; }

        public static void OpenFile(string path)
        {
            file = File.Open(path, FileMode.Append);
            fileWrite = true;
        }

        public void CloseFile()
        {
            file.Close();
            fileWrite = false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <param name="level">0-info(default,gray), 1-important info(white), 2-warning(yellow), 3-danger(red), 4-crit(dark red) </param>
        public static void Log(string input, int level)
        {
            input = "[" + DateTime.Now.ToString() + "] " + input;
            switch (level)
            {
                case 1: if (logLevel <= level) Console.ForegroundColor = ConsoleColor.White; else return; break;
                case 2: if (logLevel <= level) Console.ForegroundColor = ConsoleColor.Yellow; else return; break;
                case 3: if (logLevel <= level) Console.ForegroundColor = ConsoleColor.Red; else return; break;
                case 4: if (logLevel <= level) Console.ForegroundColor = ConsoleColor.DarkRed; else return; break;
                default: if (logLevel <= level) Console.ForegroundColor = ConsoleColor.Gray; else return; break;
            }
            Console.WriteLine(input);
            Console.ForegroundColor = ConsoleColor.Gray;
            if (fileWrite == true)
            {
                switch (level)
                {
                    case 1: if (logLevel <= level) input = "INFO     " + input; else return; break;
                    case 2: if (logLevel <= level) input = "WARNING  " + input; else return; break;
                    case 3: if (logLevel <= level) input = "DANGER   " + input; else return; break;
                    case 4: if (logLevel <= level) input = "CRITICAL " + input; else return; break;
                    default: if (logLevel <= level) input = "info     " + input; else return; break;
                }

                lock (file)
                {
                    
                    byte[] bytes = Encoding.Unicode.GetBytes(input + "\r\n");
                    file.Write(bytes, 0, bytes.Length);
                    file.Flush();
                }
            }
        }

        public static void Log(string input)
        {
            input = "[" + DateTime.Now.ToString() + "] " + input;
            if (logLevel <= 0)
            {
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine(input);
            }

            if (fileWrite == true)
            {
                if (logLevel <= 0) input = "info     " + input; else return;
                lock (file)
                {
                    byte[] bytes = Encoding.Unicode.GetBytes(input + "\r\n");
                    file.Write(bytes, 0, bytes.Length);
                    file.Flush();
                }
            }
        }
    }
}
