using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Timers;
using Microsoft.Win32;

namespace SetupKeeper
{
    public partial class SetupKeeper : ServiceBase
    {
        public enum ServiceState
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ServiceStatus
        {
            public int dwServiceType;
            public ServiceState dwCurrentState;
            public int dwControlsAccepted;
            public int dwWin32ExitCode;
            public int dwServiceSpecificExitCode;
            public int dwCheckPoint;
            public int dwWaitHint;
        };

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceStatus(System.IntPtr handle, ref ServiceStatus serviceStatus);

        public SetupKeeper()
        {
            InitializeComponent();

            // EventLog.Delete("SetupKeeper");
            // EventLog.DeleteEventSource("SetupKeeper");
            eventLog = new EventLog();
            eventLog.Source = "Setup Keeper";
            eventLog.Log = "Setup Keeper";
            /*
            if (EventLog.SourceExists(EventLog.Source))
                EventLog.DeleteEventSource(eventLog.Source);
            */
            if (!EventLog.SourceExists(eventLog.Source))
            {
                EventLog.CreateEventSource(eventLog.Source, eventLog.Log);
            }
        }

        internal void RunInteractive()
        {
            this.OnStart(null);
            Console.ReadLine();
            this.OnStop();
        }

        protected override void OnStart(string[] args)
        {
            eventLog.WriteEntry("SetupKeeper starting");

            // Update the service state to Start Pending.
            ServiceStatus serviceStatus = new ServiceStatus();
            serviceStatus.dwCurrentState = ServiceState.SERVICE_START_PENDING;
            serviceStatus.dwWaitHint = 5000;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);

            // Set up a timer that triggers every minute.
            Timer timer = new Timer
            {
                Interval = 15000 // 15 seconds
            };
            timer.Elapsed += new ElapsedEventHandler(this.OnTimer);
            timer.Start();

            // Update the service state to Running.
            serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);

            OnTimer(null, null); // dump once immediately
        }

        public void OnTimer(object sender, ElapsedEventArgs args)
        {
            StringBuilder message = new StringBuilder();
            DumpRegistry(message, @"SYSTEM\Setup\Status\ChildCompletion");
            message.Append("\r\n");
            DumpRegistry(message, @"SYSTEM\Setup\Status\SysprepStatus");
            message.Append("\r\n");
            DumpRegistry(message, @"SYSTEM\Setup\Status\UnattendPasses");

            eventLog.WriteEntry(message.ToString(), EventLogEntryType.Information);
        }

        private static void DumpRegistry(StringBuilder message, String hklmPath)
        {
            message.AppendFormat("{0}:\r\n", hklmPath);
            RegistryKey key = Registry.LocalMachine.OpenSubKey(hklmPath);
            foreach (var value in key.GetValueNames())
            {
                message.AppendFormat("\t{0}: {1}\r\n", value, key.GetValue(value));
            }
        }

        protected override void OnStop()
        {
            eventLog.WriteEntry("SetupKeeper stopping");

            // Update the service state to Stop Pending.
            ServiceStatus serviceStatus = new ServiceStatus();
            serviceStatus.dwCurrentState = ServiceState.SERVICE_STOP_PENDING;
            serviceStatus.dwWaitHint = 5000;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);

            // Update the service state to Stopped.
            serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);
        }

    }
}
