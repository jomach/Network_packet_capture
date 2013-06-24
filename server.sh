import SocketServer, ConfigParser

global configuration_file
configuration_file=None

class MyTCPHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        print "{} wrote:".format(self.client_address[0])
        print self.data
        # just send back the same data, but upper-cased
        self.request.sendall(self.data.upper())

def load_config():
    
    #load and apply configs from file 
    try:
        global configuration_file
        configuration_file = ConfigParser.RawConfigParser()
        configuration_file.read('./logger_settings/logger.cfg')
    except ConfigParser.NoSectionError:
        print "I cannot find the logger.cfg file. Make sure that is in ./logger_settings/logger.cfg"
        sys.exit()

if __name__ == "__main__":
    load_config()
    HOST, PORT = "localhost", configuration_file.getint('General','encrypt_port')
    print PORT

    # Create the server, binding to localhost on port 9999
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()