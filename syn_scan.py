# usage: syn_scan hostName

import socket
import sys
import concurrent.futures
import struct

def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8 )
        s = s + w

    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

def make_ip_header():
    ip_version = 4
    ip_ihl = 5
    ip_typeOfService = 0
    ip_length = 60
    ip_id = 23884
    ip_res_flag = 0
    ip_dont_frag = 1
    ip_more_frags = 0
    ip_fragment_offset = (ip_more_frags << 13) + (ip_dont_frag << 14) + (ip_res_flag << 15) + 0
    ip_ttl = 64
    ip_protocol = socket.IPPROTO_TCP
    ip_checksum = 0
    ip_src_addr = socket.inet_aton('192.168.1.1')
    ip_dst_addr = socket.inet_aton(dst_addr)

    ip_ihl_v = (ip_version << 4) + ip_ihl

    header  = struct.pack('!BBHHHBBH4s4s', ip_ihl_v, ip_typeOfService, ip_length, ip_id, ip_fragment_offset, ip_ttl, ip_protocol, ip_checksum, ip_src_addr, ip_dst_addr)
    return header

def make_psuedo_header(tcp_header):
    psd_src_addr = socket.inet_aton('192.168.1.1')
    psd_dst_addr = socket.inet_aton(dst_addr)
    psd_reserved = 0
    psd_protocol = socket.IPPROTO_TCP
    psd_tcp_len = len(tcp_header)
    header = struct.pack('!4s4sBBH', psd_src_addr, psd_dst_addr, psd_reserved, psd_protocol, psd_tcp_len)
    return header

def make_tcp_header(portNum):
    # fields for tcp_header
    tcp_src_prt = 65123
    tcp_dst_prt = portNum
    tcp_seq_number = 454
    tcp_ack_number = 0
    tcp_doff = 5

    tcp_urg_flag = 0
    tcp_ack_flag = 0
    tcp_psh_flag = 0
    tcp_rst_flag = 0
    tcp_syn_flag = 1
    tcp_fin_flag = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin_flag + (tcp_syn_flag << 1) + (tcp_rst_flag << 2) + (tcp_psh_flag << 3) + (tcp_ack_flag << 4) + (tcp_urg_flag << 5)

    tcp_window_sz = socket.htons(5840)
    tcp_checksum = 0
    tcp_urgent_ptr = 0

    #build first version of tcp_header
    tmpheader = struct.pack('!HHLLBBHHH', tcp_src_prt, tcp_dst_prt, tcp_seq_number, tcp_ack_number, tcp_offset_res, tcp_flags, tcp_window_sz, tcp_checksum, tcp_urgent_ptr)
    #build psuedo-header    
    psd = make_psuedo_header(tmpheader)
    
    #calculate checksum
    tcp_checksum = checksum(psd)

    # build final tcp_header using calculated checksum (not sent in network bytes)
    header = struct.pack('!HHLLBBH', tcp_src_prt, tcp_dst_prt, tcp_seq_number, tcp_ack_number, tcp_offset_res, tcp_flags, tcp_window_sz) + struct.pack('H', tcp_checksum)  + struct.pack('!H', tcp_urgent_ptr)
    
    return header


def scan_port(portNum):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # build ip header
        ip_header = make_ip_header()

        # build tcp header
        tcp_header = make_tcp_header(portNum)
        
        # make packet
        packet = ip_header + tcp_header

        # send packet
        print("sending packet to ip address: " + str(dst_addr))
        sock.sendto(packet, (dst_addr, 0))

    except socket.error as e:
        print("socket error: " + str(portNum) + ": " + str(e))

hostname = sys.argv[1]
dst_addr = socket.gethostbyname(hostname)
p = sys.argv[2]

scan_port(int(p))
