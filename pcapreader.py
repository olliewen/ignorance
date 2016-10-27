
import dpkt

f = open('mb_testpackets.pcap', 'rb') # open in rb otherwise it fails

pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    print ts, len(buf)
    eth = dpkt.ethernet.Ethernet(buf)
    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            print tcp.dport
