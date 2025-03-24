using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace SetupKeeper
{
    internal static class Program
    {
        /// <summary>
        /// Der Haupteinstiegspunkt für die Anwendung.
        /// </summary>
        static void Main()
        {
            if (Environment.UserInteractive) {
                SetupKeeper setupKeeper = new SetupKeeper();
                setupKeeper.RunInteractive();
            }
            else
            {
                ServiceBase[] ServicesToRun;
                ServicesToRun = new ServiceBase[]
                {
                new SetupKeeper()
                };
                ServiceBase.Run(ServicesToRun);
            }
        }
    }
}
