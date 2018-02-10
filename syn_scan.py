import socket
import sys

def scan_port(portNum):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostname = sys.argv[1]
    try:
        s.connect((hostname, portNum))
        print("success connection on port " + str(portNum))
    except socket.error as e:
        print("could not connect to port " + str(portNum) + ": " + str(e))

# add type checking of args later as fun ex
scan_port(int(sys.argv[2]))
