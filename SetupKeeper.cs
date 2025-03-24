using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
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

        [Flags]
        public enum ExitWindows : uint
        {
            // ONE of the following five:
            LogOff = 0x00,
            ShutDown = 0x01,
            Reboot = 0x02,
            PowerOff = 0x08,
            RestartApps = 0x40,
            // plus AT MOST ONE of the following two:
            Force = 0x04,
            ForceIfHung = 0x10,
        }

        [Flags]
        enum ShutdownReason : uint
        {
            MajorApplication = 0x00040000,
            MajorHardware = 0x00010000,
            MajorLegacyApi = 0x00070000,
            MajorOperatingSystem = 0x00020000,
            MajorOther = 0x00000000,
            MajorPower = 0x00060000,
            MajorSoftware = 0x00030000,
            MajorSystem = 0x00050000,

            MinorBlueScreen = 0x0000000F,
            MinorCordUnplugged = 0x0000000b,
            MinorDisk = 0x00000007,
            MinorEnvironment = 0x0000000c,
            MinorHardwareDriver = 0x0000000d,
            MinorHotfix = 0x00000011,
            MinorHung = 0x00000005,
            MinorInstallation = 0x00000002,
            MinorMaintenance = 0x00000001,
            MinorMMC = 0x00000019,
            MinorNetworkConnectivity = 0x00000014,
            MinorNetworkCard = 0x00000009,
            MinorOther = 0x00000000,
            MinorOtherDriver = 0x0000000e,
            MinorPowerSupply = 0x0000000a,
            MinorProcessor = 0x00000008,
            MinorReconfig = 0x00000004,
            MinorSecurity = 0x00000013,
            MinorSecurityFix = 0x00000012,
            MinorSecurityFixUninstall = 0x00000018,
            MinorServicePack = 0x00000010,
            MinorServicePackUninstall = 0x00000016,
            MinorTermSrv = 0x00000020,
            MinorUnstable = 0x00000006,
            MinorUpgrade = 0x00000003,
            MinorWMI = 0x00000015,

            FlagUserDefined = 0x40000000,
            FlagPlanned = 0x80000000
        }

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool ExitWindowsEx(ExitWindows uFlags, ShutdownReason dwReason);
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
                Interval = 10000 // 15 seconds
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
            RegistryKey setupStatus = Registry.LocalMachine.OpenSubKey(@"SYSTEM\Setup\Status");
            StringBuilder message = new StringBuilder();
            RegistryKey childCompletion = setupStatus.OpenSubKey(@"ChildCompletion");
            DumpRegistry(message, childCompletion);
            message.AppendLine();
            DumpRegistry(message, setupStatus.OpenSubKey(@"SysprepStatus"));
            message.AppendLine();
            DumpRegistry(message, setupStatus.OpenSubKey(@"UnattendPasses"));
            message.AppendLine();
            message.AppendFormat("Volatile: {0}", setupStatus.OpenSubKey(@"Volatile") != null).AppendLine();
            eventLog.WriteEntry(message.ToString(), EventLogEntryType.Information);

            // ChildCompletion\SetupFinalTask == 1 && Volatile exists
            if (Convert.ToInt32(childCompletion.GetValue("SetupFinalTasks")) == 1 && setupStatus.OpenSubKey(@"Volatile") != null)
            {
                OnArmed();
            }
        }

        private long lastLength = 0;
        private int sameLength = 0;
        private void OnArmed()
        {
            eventLog.WriteEntry("Detected Setup phase to be handled", EventLogEntryType.Information);

            string setupActPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"Panther\setupact.log");

            long length = (new FileInfo(setupActPath)).Length;

            if (length == lastLength)
                sameLength++;
            else {
                sameLength = 0;
                lastLength = length;
            }

            eventLog.WriteEntry(String.Format("{0} has {1} bytes (same: {2})", setupActPath, length, sameLength));

            if (sameLength > 3)
            {
                eventLog.WriteEntry(String.Format("{0} not growing - Setup has settled - give it a kick", setupActPath));

                // Reboot!
                ExitWindowsEx(
                    ExitWindows.Reboot | ExitWindows.Force,
                    ShutdownReason.MajorOperatingSystem | ShutdownReason.MinorInstallation | ShutdownReason.FlagPlanned);
            }
        }

        private static void DumpRegistry(StringBuilder message, RegistryKey key)
        {
            message.AppendFormat("{0}:\r\n", key.Name);
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
