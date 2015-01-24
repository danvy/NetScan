using System;
using System.Linq;
using System.Net;
using System.Reflection;

namespace NetScan
{
    class Program
    {
        private static bool cancel = false;
        private static bool onlyPI = false;
        static void Main(string[] args)
        {
            Console.CancelKeyPress += Console_CancelKeyPress;
            Console.WriteLine(string.Format("{0} version {1}", System.AppDomain.CurrentDomain.FriendlyName, Assembly.GetExecutingAssembly().GetName().Version));
            Console.WriteLine("Your Raspberry PI scanner");
            Console.WriteLine(string.Format("Check http://github.com/netscan for more infos"));
            var onlyPIParams = new string[] { "-o", "/o", "-onlypi", "/onlypi" };
            var helpParams = new string[] { "-h", "/h", "-help", "/help" };
            for (var i = 0; i < args.Count(); i++)
            {
                if (helpParams.Contains(args[i].ToLowerInvariant()))
                {
                    Console.WriteLine(string.Format("Usage : {0} [IP] [-a|-all] [-h|-help]", System.AppDomain.CurrentDomain.FriendlyName));
                    Console.WriteLine("IP: The IP you want check using 0.0.0.0 format (ex: 192.168.1.1 10.0.0.1). We'll check all the machines on the same network.");
                    Console.WriteLine(string.Format("{0}: Display the parameters help", string.Join("|", helpParams)));
                    Console.WriteLine(string.Format("{0}: List only Raspberry PI machines. By default, all machines will be listed.", string.Join("|", onlyPIParams)));
                    return;
                }
                else if (onlyPIParams.Contains(args[i].ToLowerInvariant()))
                {
                    onlyPI = true;
                }
                else
                {
                    IPAddress paramIP;
                    if (IPAddress.TryParse(args[i], out paramIP))
                    {
                        Scan(paramIP);
                    }
                }
            }
            Scan();
#if DEBUG
            Console.ReadKey(false);
#endif
        }
        static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            cancel = true;
        }
        static void Scan(IPAddress paramIP = null, bool all = true)
        {
            var localIP = paramIP ?? IPAddressHelper.GetLocalIP();
            if (localIP == null)
                throw new Exception(string.Format("Can't find network adapter for IP {0}", paramIP));
            var localMask = localIP.GetSubnetMask();
            if (localMask == null)
                throw new Exception(string.Format("Can't find subnet mask for IP {0}", localIP));
            var localMac = localIP.GetMac();
            Console.WriteLine(string.Format("Local IP={0}, Mask={1}, Mac={2}", localIP.ToString(), localMask.ToString(), localMac));
            var segment = new IPSegment(localIP, localMask);
#if DEBUG
            Console.WriteLine(string.Format("Number of IPs={0}, NetworkAddress={1}, Broardcast={2}", segment.NumberOfIPs, segment.NetworkAddress, segment.BroadcastAddress));
#endif
            foreach (var ip in segment.Hosts())
            {
                if (cancel)
                    break;
                var mac = ip.GetMac();
                //All Raspberry PI MAC address start with the same prefix
                var spotted = mac.ToString().ToUpper().StartsWith("B8:27:EB");
                if ((onlyPI && spotted) || !onlyPI)
                    Console.WriteLine(string.Format("IP={0} MAC={1}{2}", ip, mac, spotted ? " <- Raspberry PI spotted !!!" : ""));
            }
        }
    }
}
