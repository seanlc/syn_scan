import socket
import sys
import concurrent.futures

def scan_port(portNum):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostname = sys.argv[1]
    try:
        s.connect((hostname, portNum))
        print("success connection on port " + str(portNum))
    except socket.error as e:
        pass
#        print("could not connect to port " + str(portNum) + ": " + str(e))

# add type checking of args later as fun ex

lowP = int(input("Enter the low end of port range: "))
highP = int(input("Enter the high end of port range: "))


with concurrent.futures.ThreadPoolExecutor(max_workers = 256) as executor:
    for p in range(lowP,highP):
        executor.submit(scan_port, p)

