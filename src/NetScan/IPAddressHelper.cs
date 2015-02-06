// Coded by Alex Danvy
// http://danvy.tv
// http://twitter.com/danvy
// http://github.com/danvy
// Licence Apache 2.0
// Use at your own risk, have fun

using System;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace NetScan
{
    public static class IPAddressHelper
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
        public static IPAddress GetBroadcastAddress(this IPAddress ip, IPAddress mask)
        {
            var ipBytes = ip.GetAddressBytes();
            var maskBytes = mask.GetAddressBytes();
            if (ipBytes.Length != maskBytes.Length)
                throw new ArgumentException("Lengths of IP address and subnet mask do not match.");
            var broadcast = new byte[ipBytes.Length];
            for (int i = 0; i < broadcast.Length; i++)
            {
                broadcast[i] = (byte)(ipBytes[i] | (maskBytes[i] ^ 255));
            }
            return new IPAddress(broadcast);
        }
        public static IPAddress GetNetworkAddress(this IPAddress ip, IPAddress mask)
        {
            byte[] ipBytes = ip.GetAddressBytes();
            byte[] maskBytes = mask.GetAddressBytes();
            if (ipBytes.Length != maskBytes.Length)
                throw new ArgumentException("Lengths of IP address and subnet mask do not match.");
            byte[] network = new byte[ipBytes.Length];
            for (int i = 0; i < network.Length; i++)
            {
                network[i] = (byte)(ipBytes[i] & (maskBytes[i]));
            }
            return new IPAddress(network);
        }
        public static IPAddress GetSubnetMask(this IPAddress address)
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var unicastIP in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (unicastIP.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        if (address.Equals(unicastIP.Address))
                        {
                            return unicastIP.IPv4Mask;
                        }
                    }
                }
            }
            return null;
        }
        public static IPAddress GetLocalIP()
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(o=>o.OperationalStatus==OperationalStatus.Up))
            {
                var prop = nic.GetIPProperties();
                var address = prop.GatewayAddresses.FirstOrDefault();
                if (address != null)
                {
                    var unicast = prop.UnicastAddresses.Where((o) => o.Address.AddressFamily == AddressFamily.InterNetwork).FirstOrDefault();
                    if (unicast != null)
                        return unicast.Address;
                }
            }
            return null;
        }
        public static string GetMac(this IPAddress ip, int retryCount = 3)
        {
            var destIP = ip.ToUInt32();
            var mac = new byte[6];
            var macLen = mac.Length;
            for (var j = 0; j < 3; j++)
            {
                var rc = SendARP(destIP, 0, mac, ref macLen);
                if (rc == 0)
                {
                    var str = new string[macLen];
                    for (int i = 0; i < macLen; i++)
                        str[i] = mac[i].ToString("x2");
                    return string.Join(":", str);
                }
            }
            return string.Empty;
        }
        public static bool IsInSameSubnet(this IPAddress address2, IPAddress address, IPAddress subnetMask)
        {
            IPAddress network1 = address.GetNetworkAddress(subnetMask);
            IPAddress network2 = address2.GetNetworkAddress(subnetMask);
            return network1.Equals(network2);
        }
        public static UInt32 ToUInt32(this IPAddress ip)
        {
            return BitConverter.ToUInt32(ip.GetAddressBytes(), 0);
        }
        public static void ScanMac(Action<IPAddress, string> callBack, CancellationToken ct, IPAddress paramIP = null)
        {
            if (callBack == null)
                throw new ArgumentNullException(string.Format("Callback needed"));
            var localIP = paramIP ?? IPAddressHelper.GetLocalIP();
            if (localIP == null)
                throw new Exception(string.Format("Can't find network adapter for IP {0}", paramIP));
            var localMask = localIP.GetSubnetMask();
            if (localMask == null)
                throw new Exception(string.Format("Can't find subnet mask for IP {0}", localIP));
            var localMac = localIP.GetMac();
            Debug.WriteLine(string.Format("Local IP={0}, Mask={1}, Mac={2}", localIP.ToString(), localMask.ToString(), localMac));
            var segment = new IPSegment(localIP, localMask);
            Debug.WriteLine(string.Format("Number of IPs={0}, NetworkAddress={1}, Broardcast={2}", segment.NumberOfIPs, segment.NetworkAddress, segment.BroadcastAddress));
            ParallelOptions po = new ParallelOptions();
            po.CancellationToken = ct;
            po.MaxDegreeOfParallelism = System.Environment.ProcessorCount;
            try
            {
                Parallel.ForEach<IPAddress>(segment.Hosts(), po, (ip) =>
                {
                    var mac = ip.GetMac();
                    if (mac.Length > 0)
                        callBack.Invoke(ip, mac);
                    if (po.CancellationToken != null)
                        po.CancellationToken.ThrowIfCancellationRequested();
                });
            }
            catch (OperationCanceledException e)
            {
                Debug.WriteLine(e.Message);
            }
        }
    }
    public static class UInt16Helper
    {
        public static UInt16 ReverseBytes(UInt16 value)
        {
            return (UInt16)((value & 0xFFU) << 8 | (value & 0xFF00U) >> 8);
        }
    }
    public static class UInt32Helper
    {
        public static IPAddress ToIPAddress(this UInt32 ip)
        {
            return new IPAddress(BitConverter.GetBytes(ip));
        }
        public static UInt32 ReverseBytes(this UInt32 value)
        {
            return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
                   (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
        }
    }
    public static class UInt64Helper
    {
        public static UInt64 ReverseBytes(this UInt64 value)
        {
            return (value & 0x00000000000000FFUL) << 56 | (value & 0x000000000000FF00UL) << 40 |
                   (value & 0x0000000000FF0000UL) << 24 | (value & 0x00000000FF000000UL) << 8 |
                   (value & 0x000000FF00000000UL) >> 8 | (value & 0x0000FF0000000000UL) >> 24 |
                   (value & 0x00FF000000000000UL) >> 40 | (value & 0xFF00000000000000UL) >> 56;
        }
    }
}
