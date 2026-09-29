#!/usr/bin/env python3
import struct
import time
import os

OUT = 'out/dhcp.pcapng'
# ensure out dir
os.makedirs('out', exist_ok=True)

def ip_checksum(header: bytes) -> int:
    if len(header) % 2 == 1:
        header += b'\x00'
    s = sum(struct.unpack('!' + 'H'*(len(header)//2), header))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

# pcap global header (libpcap) - will be readable by tshark
pcap_global_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
# helper to write a packet record (tssec, tsusec, incl_len, orig_len, data)
def pcap_packet(ts, data):
    tssec = int(ts)
    tsusec = int((ts - tssec) * 1_000_000)
    hdr = struct.pack('<IIII', tssec, tsusec, len(data), len(data))
    return hdr + data

# build packet bytes for DHCP messages
ETH_DST = b'\xff\xff\xff\xff\xff\xff'
ETH_SRC = b'\x00\x11\x22\x33\x44\x55'
ETH_TYPE_IP = b'\x08\x00'

CLIENT_MAC = b'\x00\x11\x22\x33\x44\x55' + b'\x00'*10

# BOOTP fixed size 236
BOOTFIX = 236

magic = b'\x63\x82\x53\x63'
# options: DHCP Message Type option
opt_disc = magic + b'\x35\x01\x01' + b'\xff'
opt_offer = magic + b'\x35\x01\x02' + b'\xff'
opt_req   = magic + b'\x35\x01\x03' + b'\xff'
opt_ack   = magic + b'\x35\x01\x05' + b'\xff'

# helper to build an ethernet+ip+udp+bootp packet
import random

def build_dhcp_packet(msgtype_opts, yiaddr=b'\x00\x00\x00\x00', xid=None):
    if xid is None:
        xid = random.randint(0, 0xffffffff)
    # BOOTP header
    op = 1 if msgtype_opts is opt_disc or msgtype_opts is opt_req else 2
    htype = 1
    hlen = 6
    hops = 0
    secs = 0
    flags = 0x0000
    ciaddr = b'\x00\x00\x00\x00'
    siaddr = b'\x00\x00\x00\x00'
    giaddr = b'\x00\x00\x00\x00'
    chaddr = CLIENT_MAC
    sname = b'\x00'*64
    fileb = b'\x00'*128
    bootp_fixed = struct.pack('!BBBBIHH4s4s4s4s16s64s128s',
                              op, htype, hlen, hops, xid, secs, flags,
                              ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, fileb)
    payload = bootp_fixed + msgtype_opts
    # UDP header
    src_port = 68 if op == 1 else 67
    dst_port = 67 if op == 1 else 68
    udp_len = 8 + len(payload)
    udp_cksum = 0
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, udp_cksum)
    # IP header
    ver_ihl = 0x45
    tos = 0
    total_len = 20 + udp_len
    identification = 0
    flags_frag = 0
    ttl = 64
    proto = 17
    checksum = 0
    src_ip = b'\x00\x00\x00\x00' if op == 1 else b'\xc0\xa8\x01\x01'  # offer/ack from 192.168.1.1
    dst_ip = b'\xff\xff\xff\xff' if op == 1 else b'\x00\x00\x00\x00'
    ip_header_wo_ck = struct.pack('!BBHHHBBH4s4s', ver_ihl, tos, total_len, identification,
                                  flags_frag, ttl, proto, checksum, src_ip, dst_ip)
    checksum = ip_checksum(ip_header_wo_ck)
    ip_header = struct.pack('!BBHHHBBH4s4s', ver_ihl, tos, total_len, identification,
                                  flags_frag, ttl, proto, checksum, src_ip, dst_ip)
    frame = ETH_DST + ETH_SRC + ETH_TYPE_IP + ip_header + udp_header + payload
    return frame

# build four packets with increasing timestamps
now = time.time()
pkts = []
# Discover
pkts.append((now, build_dhcp_packet(opt_disc, yiaddr=b'\x00\x00\x00\x00', xid=0x3903F326)))
# Offer (reply from server, yiaddr offered)
pkts.append((now+1, build_dhcp_packet(opt_offer, yiaddr=b'\xc0\xa8\x01\x64', xid=0x3903F326)))
# Request
pkts.append((now+2, build_dhcp_packet(opt_req, yiaddr=b'\x00\x00\x00\x00', xid=0x3903F326)))
# Ack
pkts.append((now+3, build_dhcp_packet(opt_ack, yiaddr=b'\xc0\xa8\x01\x64', xid=0x3903F326)))

with open(OUT, 'wb') as f:
    f.write(pcap_global_header)
    for ts, data in pkts:
        f.write(pcap_packet(ts, data))

print('wrote', OUT)
