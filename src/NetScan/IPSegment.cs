using System;
using System.Collections.Generic;
using System.Net;

namespace NetScan
{
    class IPSegment
    {
        private UInt32 ip;
        private UInt32 mask;
        private UInt32 networkAddress;
        private UInt32 broadcastAddress;
        public IPSegment(IPAddress ip, IPAddress mask)
        {
            this.ip = ip.ToUInt32();
            this.mask = mask.ToUInt32();
            networkAddress = this.ip & this.mask;
            broadcastAddress = networkAddress + ~this.mask;
        }
        public UInt32 NumberOfIPs
        {
            get
            {
                return ~(mask.ReverseBytes()) - 1;
            }
        }

        public IPAddress NetworkAddress
        {
            get
            {
                return networkAddress.ToIPAddress();
            }
        }
        public IPAddress BroadcastAddress
        {
            get
            {
                return broadcastAddress.ToIPAddress();
            }
        }
        public IEnumerable<IPAddress> Hosts()
        {
            var net = networkAddress.ReverseBytes();
            var broad = broadcastAddress.ReverseBytes();
            for (var host = net + 1; host < broad; host++)
            {
                yield return host.ReverseBytes().ToIPAddress();
            }
        }
    }
}
