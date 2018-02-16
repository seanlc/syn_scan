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

def scan_port(portNum):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    try:
#        s.connect((hostname, portNum))

        # msg to be sent
        msg = b'hello world'

        # build ip header
        ip_version = 4
        ip_ihl = 5
        ip_typeOfService = 0
        ip_length = 52
        ip_id = 23884
        ip_fragment_offset = 0
        ip_ttl = 128
        ip_protocol = socket.IPPROTO_TCP
        ip_checksum = 0
        ip_src_addr = socket.inet_aton(socket.gethostbyname("www.google.com"))
        ip_dst_addr = socket.inet_aton(dst_addr)

        ip_ihl_v = (ip_version << 4) + ip_ihl

        ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_v, ip_typeOfService, ip_length, ip_id, ip_fragment_offset, ip_ttl, ip_protocol, ip_checksum, ip_src_addr, ip_dst_addr)

        # build tcp header

        tcp_src_prt = 65123
        tcp_dst_prt = portNum
        tcp_seq_number = 0
        tcp_ack_number = 0
        tcp_doff = 5

        tcp_urg_flag = 0
        tcp_ack_flag = 0
        tcp_psh_flag = 0
        tcp_rst_flag = 0
        tcp_syn_flag = 1
        tcp_fin_flag = 0

        tcp_offset_res = (tcp_doff << 4)
        tcp_flags = tcp_fin_flag + (tcp_syn_flag << 1) + (tcp_rst_flag << 2) + (tcp_psh_flag << 3) + (tcp_ack_flag << 4) + (tcp_urg_flag << 5)

        tcp_window_sz = 64240
        tcp_checksum = 0
        tcp_urgent_ptr = 0

        tcp_header = struct.pack('!HHLLBBHHH', tcp_src_prt, tcp_dst_prt, tcp_seq_number, tcp_ack_number, tcp_offset_res, tcp_flags, tcp_window_sz, tcp_checksum, tcp_urgent_ptr)

        # construct psuedo header

        psd_src_addr = ip_src_addr
        psd_dst_addr = ip_dst_addr
        psd_reserved = 0
        psd_protocol = socket.IPPROTO_TCP
        psd_tcp_len = len(tcp_header) + len(msg)

        psd = struct.pack('!4s4sBBH', psd_src_addr, psd_dst_addr, psd_reserved, psd_protocol, psd_tcp_len)
        tcp_checksum = checksum(psd)

        tcp_header = struct.pack('!HHLLBBH', tcp_src_prt, tcp_dst_prt, tcp_seq_number, tcp_ack_number, tcp_offset_res, tcp_flags, tcp_window_sz) + struct.pack('H', tcp_checksum)  + struct.pack('!H', tcp_urgent_ptr)
        
        packet = ip_header + tcp_header + msg

        print("sending packet to ip address: " + str(dst_addr))
        sock.sendto(packet, (dst_addr, 0))

        print("success connection on port " + str(portNum))
    except socket.error as e:
##        pass
        print("could not connect to port " + str(portNum) + ": " + str(e))

# add type checking of args later as fun ex

#lowP = int(input("Enter the low end of port range: "))
#highP = int(input("Enter the high end of port range: "))

hostname = sys.argv[1]
dst_addr = socket.gethostbyname(hostname)

p = sys.argv[2]

#with concurrent.futures.ThreadPoolExecutor(max_workers = 256) as executor:
    #for p in range(lowP,highP):

#    executor.submit(scan_port, p)
scan_port(int(p))
