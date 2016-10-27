
import dpkt

f = open('mb_testpackets.pcap', 'rb') # open in rb otherwise it fails

pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    print ts, len(buf)
