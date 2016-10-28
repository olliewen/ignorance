from scapy.all import *
import sys

#tcpFile = open('TCPpcap.txt', 'w')

def getTCPPackets(pcapFile,use):

    pkts = rdpcap(pcapFile)
    print pkts
    #a = hexdump(pkts[0])
    #b = Ether(a)

    if use == None or use == "":
        use = 0

    ############################
    ########## PROTO ###########
    ############################
    ######### TCP = 6 ##########
    ######### UDP = 17 #########
    ############################

    tcpPkts = []

    if use == 0:
        for pkt in pkts:
            if IP in pkt and TCP in pkt:
                tcpPkts.append(pkt)
        return tcpPkts
    elif use ==1:
        printPacketBreak(pkts)
    else:
        pass

def printPacketBreak(pkts):

    f = ""

    for pkt in pkts:
        if IP in pkt and TCP in pkt:
            if f == "q":
                sys.exit()
            elif pkt[IP].proto == 6:
                #tcpFile.write()
                print pkt.time
                printPacketInfo(pkt)

                f = raw_input("q to quit: ")
            else:
                pass

def printPacketInfo(pkt):
    print pkt.show()
