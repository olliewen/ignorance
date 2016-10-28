
import dpkt

class DataConnection(object):
    def __init__(self, src, dest, sport, dport):
        self.src = src
        self.dest = dest
        self.sport = sport
        self.dport = dport

    def __hash__(self):
        return hash((self.src, self.dest, self.sport, self.dport))

    def __eq__(self, other):
        return self.src == other.src and self.dest == other.dest and self.sport == other.sport and self.dport == other.dport


def open_pcap(pcap_file):
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