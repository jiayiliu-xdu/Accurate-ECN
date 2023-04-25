from scapy.all import *
import sys, os

TYPE_IPV4 = 0x0800
TCP_PROTOCOL = 0x06
TCP_INT = 0x7


class IntShim(Packet):
    fields_desc = [BitField("type", 1, 4),
                   BitField("npt", 0, 2),
                   BitField("shimRsvd1", None, 2),
                   XByteField("length", None),
                   XByteField("shimRsvd2", None),
                   BitField("dscp", None, 6),
                   BitField("shimRsvd3", None, 2)]

class Metadata(Packet):
    fields_desc = [ IntField("swid", 0),
                  IntField("hop_latency", 0),
                  XByteField("ingress_tstamp", None),
                  XByteField("egress_tstamp", None)
                  ]
    def extract_padding(self, p):
                return "", p


class Int(Packet):
    name = "INT"
    fields_desc = [IntShim,
                   # header INT
                   BitField("ver", 2, 4),
                   BitField("d", 0, 1),
                   BitField("e", 0, 1),
                   BitField("m", 0, 1),
                   BitField("rsvd1", None, 12),
                   BitField("hopML", None, 5),
                   BitField("count", 0, 8),
                   XByteField("ins", None), 
                   XShortField("rsvd2", None),
                   # INT metadata
                   PacketListField("metedata",
                                   [],
                                   Metadata,
                                   count_from=lambda pkt:(pkt.count*1))
    ]
    

bind_layers(TCP, Int, reserved=TCP_INT)

