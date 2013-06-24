import socket
import sys

HOST, PORT = "10.0.0.2", 9250
data2 = " ".join(sys.argv[1:])
data = "HELLO"
# Create a socket (SOCK_STREAM means a TCP socket)
if sys.argv[1:] != "":
		    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		    # Connect to server and send data
		    sock.connect((HOST, PORT))
		    sock.sendall(data + "\n")
		    # Receive data from the server and shut down
		    received = sock.recv(1024)
		    print "Data from HELLO {}".format(received)
		    if received[:7] =="MSG_SRV":
		    	print "MSG_SRV ok !"
		    print "sending next message"
		    sock.sendall("REGISTER:L:logger1\n")
		    received = sock.recv(1024)
		    print "Data from register:  {}".format(received)
		    
		    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		    sock.connect((HOST, PORT))
		    
		    sock.sendall(data + "\n")
		    received = sock.recv(1024)
		    print "Data from HELLO {}".format(received)
		    sock.sendall("REQ_ENCRYPT:49f546f1303eab0f1d8f345f80edf7f09bc04e9e:logger1:"+data2+"\n")
		    received = sock.recv(1024)
		    print "Data from register:  {}".format(received)
		    sock.close()

"""if sys.argv[1:] == 1:
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    # Connect to server and send data
    sock.connect((HOST, PORT))
    sock.sendall("ENCRYPT:12sdasdjk12kldf:logger1:/logger/daemonglogger.pcap.12322323123:512000000000")

    # Receive data from the server and shut down
    received = sock.recv(1024)
    print "Data from ENCRYPT {}".format(received)
    if received[:7] =="MSG_SRV":
    	print "MSG_SRV ok !"
    print "sending next message"
    sock.sendall("REGISTER:10.0.0.1\n")
    received = sock.recv(1024)
    print "Data from register:  {}".format(received)
finally:
    sock.close()"""




		#print "Sent:     {}".format(data)
		#print "Received: {}".format(received)
