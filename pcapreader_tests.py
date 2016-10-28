import unittest
import pcapreader as pr

class PcapReaderTests(unittest.TestCase):

    def test_connection_streams_are_correctly_grouped(self):
        streams = pr.getStreamsFromPcap("test_tcp_onestream.pcap")
        self.assertEqual(len(streams), 1)

    def test_connection_streams_are_correctly_separated(self):
        streams = pr.getStreamsFromPcap("test_tcp_twostream.pcap")
        self.assertEqual(len(streams), 2)