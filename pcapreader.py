
import dpkt
import binascii

class DataConnection(object):
    def __init__(self, src, dest, sport, dport):
        self.src_dest = frozenset([src, dest])
        #self.src_dest.sort()
        self.ports = frozenset([sport, dport])

    def __hash__(self):
        return hash((self.src_dest, self.ports))

    def __eq__(self, other):
        return self.src_dest == other.src_dest and self.ports == other.ports
def decode_mac(ascii):
    hex = binascii.hexlify(ascii)
    macList = list()
    for i in range(6):
        macList.append(hex[i*2:i*2+2]) # split string into pieces of two chars

    return ":".join(macList)

def open_pcap(pcap_file):
    """Open a pcap file, returns a dpkt.pcap.Reader object"""
    f = open(pcap_file, 'rb') # open in rb otherwise it fails
    pcap = dpkt.pcap.Reader(f)
    return pcap

def getStreams(pcap):
    """return: a list of connections that are themselves a list of dpkt.ethernet.Ethernet objects (the tcp segments)"""
    streamDict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                eth.src = decode_mac(eth.src)
                eth.dst = decode_mac(eth.dst)
                src, dest = eth.src, eth.dst
                sport, dport = tcp.sport, tcp.dport
                dc = DataConnection(src, dest, sport, dport)

                if dc in streamDict:
                    streamDict[dc].append(eth)
                else:
                    streamDict[dc] = [eth]

    return streamDict.values()

def getStreamsFromPcap(pcap_file):
    """Use this method to get connection streams from a pcap file"""
    pcap = open_pcap(pcap_file)
    return getStreams(pcap)
    # [[dpkt.ethernet.Ethernet(src=..., dest=..., data=...)],[],[]]