import SocketServer, ConfigParser, sys, signal, socket, thread, time
from multiprocessing import Process, Lock
from Crypto.Hash import SHA
from multiprocessing import Queue
global configuration_file
configuration_file=None
global conn
conn = None
global encryptors
global queue_to_encrypt
global loggers
global server
global lock
global automatic_distri
class Encrypt_server:
    name = None
    ip_adresse = None
    port = 0
    key  = None
    processes = 0
    running = 0
    encryption_running = []
    lock = Lock()


    def get_running_processes(self):
        return self.running

    def unresgister_from_my_self(self):
        global encryptors
        received = ""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect( ( self.ip_adresse , int(self.port) ))
            sock.settimeout(4)
            #sock.settimeout(4)
            sock.sendall("HELLO"+"\n")
            received = sock.recv(1024)
            if received == "ENCRYPT_SRV":
                sock.sendall("UNREGISTER:"+self.key+"\n")
                received = sock.recv(1024)
        except socket.error:
            pass
        counter = 0
        for a in encryptors:
            if a.key == self.key and a.name == self.name:
                del encryptors[counter]
            counter = counter +1
        if received =="OK":
            print "Returning True for unresgister..."
            return True
        elif received == "WORKING":
            print "Returning False for unresgister... reason working"
            return False
        else:
            print "I cannot contact my encryptor"
            return True




    def add_work(self, request):
        global queue_to_encrypt
        #Request is like: 
        #   L:10.0.0.2:ficheiro1:5000
        diff = int(self.processes) - int(self.running)
        if (diff < 1):
            return False  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        try:
            # Connect to server and send data

            sock.connect( ( self.ip_adresse , int(self.port) ))
            sock.sendall("HELLO"+"\n")
            received = sock.recv(1024)
            splitted_request = request.split(":")
            #Request is like: 
            #   L:10.0.0.2:ficheiro1:5000
            data = ""
            try:
                data = "ENCRYPT:%s:%s:%s"%(splitted_request[1],splitted_request[2],splitted_request[3])
            except IndexError:
                print "ERROR !!!!!!!"
                sock.close()
                return False
            sock.sendall(data+"\n")
            received = sock.recv(1024)
            received = received.split(":")
            if received [0] =="ENCRYPT_STARTED":
                self.lock.acquire()
                self.running=self.running+1
                print "Appending to running encryption : %s"%(request)
                self.encryption_running.append(request)
                self.lock.release()
                sock.close()
                return True
 
            elif received[0] == "IAM_BUSY":
                print "I am busy "+self.name
                self.lock.acquire()
                self.running = self.processes
                sock.close()
                return False

            elif received[0] == "REQ_ALREADY_IN_QUEUE":
                queue_to_encrypt.remove(request)
                if self.encryption_running.count(request) == 0:
                    self.encryption_running.append(request)

                print "Request already in Queue from encryptor"
                return True
                
            else:
                print "Error on register_work. add_work()"
                sock.close()
                return False
        except (IndexError):
            print "Index Error lin 76"
        except socket.error:
            #Cannot get connection... unregister
            self.unresgister_from_my_self()        

        finally:
            sock.close()
    def get_work_in_progress(self):
        return self.encryption_running
    
    def remove_work(self,request):
        try:
            self.running = int(self.running) - int(1)
            if self.running < 0:
                self.running = 0
            self.encryption_running.remove(request)

        except ValueError:
            print "Error on Remove work"
            pass
        return True
    def generate_self_key(self):
        h = SHA.new()
        lixo=self.name+self.ip_adresse
        h.update(b'%s'%(lixo))
        self.key=h.hexdigest()
    def get_self_key(self):
        return self.key
    def is_free(self):
        diff = int(self.processes) - int(self.running)
        if diff > 0:
            return True
        return False

    def __str__(self):
        return self.ip_adresse+":"+self.name

    def __init__(self,name,ip_adresse,port, processes):
        self.name=name
        self.ip_adresse = ip_adresse
        self.processes = processes
        self.running = 0
        self.port = port
        self.generate_self_key()

class Log_server:

    name = None
    ip_adresse = None
    key = None
    

    def generate_self_key(self):
        h = SHA.new()
        lixo=self.name+self.ip_adresse
        h.update(b'%s'%(lixo))
        self.key=h.hexdigest()

    def get_self_key(self):
        return ""+self.key

    def __init__(self,name,ip_adresse):
        self.name=name
        self.ip_adresse=ip_adresse
        self.generate_self_key()    

    def __str__(self):
        return self.ip_adresse+":"+self.name


def get_free_encrytor(encryptors):
    for a in encryptors:
        if a.is_free():
            return a
    return None


def distribute_queue(queue,encryptors, lock, loop=False, sleep=60):
    #Racing function, muss perform locking....  and check loopings
    if loop ==True:
        print "Sleep in function %i"%(sleep)
        while True:
            lock.acquire()
            distributed_queue = []
            for a in queue:
                free_encryptor=get_free_encrytor(encryptors)
                if free_encryptor != None:
                    if free_encryptor.add_work(a):
                        distributed_queue.append(a)
                else:
                    print "Nothing is free or registed cannot add work : %s"%(a)
            #Remove work distributed from queue...
            for a in distributed_queue:
                queue.remove(a)
            lock.release()
            time.sleep(sleep)
    else:
        lock.acquire()
        distributed_queue = []
        flag = True
        for a in queue:
            free_encryptor=get_free_encrytor(encryptors)
            if free_encryptor != None and free_encryptor.add_work(a):
                distributed_queue.append(a)
            else:
                print "Nothing is free"
                flag = False
        #Remove work distributed from queue...
        for a in distributed_queue:
            queue.remove(a)
        print "Queue left: %s"%(queue)
        lock.release()
        return flag


def register_encryption(ip_adresse,file_to_encrypt,size,queue_to_encrypt):
        #verify if request already in queue
        element="L:"+ip_adresse+":"+file_to_encrypt+":"+size
        for a in queue_to_encrypt:
            if a==element:
                return False
        queue_to_encrypt.append(element)
        return True

def check_if_logger_registed(logger, ip,loggers):    
    for a in loggers:
        if a.name == logger and a.ip_adresse == ip:
            return a
    return False

def check_if_encryptor_registed(encryptor, ip,encryptors):    
    for a in encryptors:
        if a.name == encryptor and a.ip_adresse == ip:
            return a
    return False

def is_authenticated(key,name,ip_adresse,loggers):
    for a in loggers:
        if a.key == key and a.name == name and a.ip_adresse == ip_adresse:
            return True
    return False

def is_callback_authenticated(key,encryptors):
    for a in encryptors:
        if a.key == key:
            return a
    return False


class MyTCPHandler(SocketServer.StreamRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    def handle(self):
        global encryptors
        global configuration_file
        global lock
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls
        try :   
                print "I have RECIVED a request"
                self.data = self.rfile.readline().strip()
                if self.data =="HELLO":
                    self.wfile.write("MSG_SRV")     
                    data_from_sender=self.rfile.readline().strip().split(":")
                    if data_from_sender[0]=="" or data_from_sender[1]=="":
                        print "No data"
                        return
                    if data_from_sender[0]=="REGISTER":
                        if data_from_sender[1] =="L":
                        #Quero registar um logger
                            is_registe_logger = check_if_logger_registed(data_from_sender[2],self.client_address[0],loggers)
                            if is_registe_logger:
                                print "Already Registered"
                                self.wfile.write(data_from_sender[2]+":ALREADY_REGISTED:%s\0"%(is_registe_logger.get_self_key()))
                                print "Data to send: "+data_from_sender[2]+":REGISTED:L:%s\0"%(is_registe_logger.get_self_key())
                            else:
                                a = Log_server(data_from_sender[2],self.client_address[0])
                                loggers.append(a)
                                self.wfile.write(data_from_sender[2]+":REGISTED:L:%s\0"%(a.get_self_key()))
                                print "Data to send: "+data_from_sender[2]+":REGISTED:L:%s"%(a.get_self_key())
                                print "Logger Registered: {}".format(data_from_sender[2])
                        elif data_from_sender[1] == "E":

                            is_encrytor_registed = check_if_encryptor_registed(data_from_sender[2],self.client_address[0],encryptors)
                            if is_encrytor_registed:
                                print "Already Registered"
                                self.wfile.write(data_from_sender[2]+":ALREADY_REGISTED:"+is_encrytor_registed.get_self_key())
                                return False
                            else:
                                #verificar se foi fornecido o numeor de processos para o servidor de encryptacao
                                    
                                    if data_from_sender[4].isdigit() and data_from_sender[4]>0 and int(data_from_sender[4]) <= configuration_file.getint('General','max_encryt_processes'):
                                        a = Encrypt_server(data_from_sender[2],self.client_address[0],data_from_sender[3],data_from_sender[4])
                                        encryptors.append(a)
                                        self.wfile.write(data_from_sender[2]+":REGISTED:E:%s"%(a.get_self_key()))
                                    else:
                                        print "Wrong header, probaly max_encryt_processes parameter"
                                        self.wfile.write("WRONG_REGISTER_HEADER")
                        else:
                            print "Wrong Encrtor Header"
                            self.wfile.write("WRONG_REGISTER_HEADER")
                            #quero registar um encrpytor
                    elif data_from_sender[0] == "REQ_ENCRYPT":
                        #Check if request is authenticate
                        b = is_authenticated(data_from_sender[1],data_from_sender[2],self.client_address[0],loggers)
                        if b == True:
                            #Register encryption on queue, check if something is free and write the anwerser in the socket.
                            #String of data must be sometinh like : REQ_ENCRYPT:secretkey:name:file_to_encrypt:size
                            if register_encryption(self.client_address[0],data_from_sender[3],data_from_sender[4],queue_to_encrypt):
                                self.wfile.write("REQ_REGISTED:%s"%(data_from_sender[3]))
                                p = thread.start_new_thread(distribute_queue,(queue_to_encrypt,encryptors,lock,))
                                print "Distributing Queue in Progress..."
                                for a in encryptors:
                                    print "----- work in progress from encryptors"
                                    print "      %s"%(a.name)
                                    print "      %s"%(a.get_work_in_progress())

                            else:
                                self.wfile.write("DUPLICATED_REQUEST")
                                print "Faild to register encryption"
                        else:
                            print "NOT_AUTHORIZED"
                            self.wfile.write("NOT_AUTHORIZED")        
                    #Call_back from encrypt_server
                    elif data_from_sender[0] == "DONE":

                        print "RECIVED CALLBACK {}".format(data_from_sender)
                        a = is_callback_authenticated(key=data_from_sender[1], encryptors=encryptors)
                        print "Before remove work from the object : %s"%(a.get_work_in_progress())
                        if a != False:
                            a.remove_work("L:"+data_from_sender[3]+":"+data_from_sender[4]+":"+data_from_sender[5])
                            self.wfile.write("OK")
                            print "After remove work from the object : %s"%(a.get_work_in_progress())
                            thread.start_new_thread(distribute_queue,(queue_to_encrypt,encryptors,lock,))
                            print "Distributing Queue in Progress..."
                            for a in encryptors:
                                    print "----- work in progress from encryptors"
                                    print "      %s"%(a.name)
                                    print "      %s"%(a.get_work_in_progress())
                            return True
                        else:
                            print "NOT_AUTHORIZED"
                            self.wfile.write("NOT_AUTHORIZED") 
                    elif data_from_sender[0] =="FILE_DOES_NOT_EXIST":
                        print "RECIVED CALLBACK FILE DOES NOT EXIST {}".format(data_from_sender)
                        a = is_callback_authenticated(key=data_from_sender[1], encryptors=encryptors)
                        if a != False:
                            a.remove_work("L:"+data_from_sender[2]+":"+data_from_sender[3]+":"+data_from_sender[4])
                            self.wfile.write("OK")
                            p = thread.start_new_thread(distribute_queue,(queue_to_encrypt,encryptors,lock,))
                            print "Distributing Queue in Progress..."
                            for a in encryptors:
                                    print "----- work in progress from encryptors"
                                    print "      %s"%(a.name)
                                    print "      %s"%(a.get_work_in_progress())
                        else:
                            print "NOT_AUTHORIZED"
                            self.wfile.write("NOT_AUTHORIZED") 
                            return False
                    elif data_from_sender[0] == "UNREGISTER":

                        for a in encryptors:
                            if a.key == encrytor.key and a.client_address == encrytor.ip_adresse:
                                a.unresgister_from_my_self()
                                self.wfile.write("OK")
        except IndexError as e:
            print "Sorry from Register Header index: {}".format(data_from_sender)
            print e
            self.wfile.write("WRONG_HEADER")
                
        print "Encryptors"
        for a in encryptors:
           print "Encryptor: %s %s %s"%(a.ip_adresse, a.key, a.name)
        print "Queue to encrypt: %s"%(queue_to_encrypt)

        #print "\nQueue\n"
        #for a in queue_to_encrypt:
        #    print a
        #print "{} wrote:".format(self.client_address[0])
        #print self.data
        # Likewise, self.wfile is a file-like object used to write back
        # to the client
        #self.wfile.write(self.data.upper())

def load_config():
    
    #load and apply configs from file 
    try:
        global configuration_file
        configuration_file = ConfigParser.RawConfigParser()
        configuration_file.read('./msgsrv_setting/logger.cfg')
    except ConfigParser.NoSectionError:
        print "I cannot find the logger.cfg file. Make sure that is in ./msgsrv_setting/logger.cfg"
        sys.exit()

def signal_handler(signal, frame):
        print 'You pressed Ctrl+C!'
        global encryptors
        global server
        global automatic_distri
        positions_for_delete = []
        counter_for_up_encryptions = 0
        counter = 0
        for a in encryptors:
            if len(a.get_work_in_progress()) == 0:
                unresgister_rsp = a.unresgister_from_my_self()
                if unresgister_rsp == True:
                    positions_for_delete.append(counter)
                elif unresgister_rsp == "WORKING":
                    counter_for_up_encryptions = counter_for_up_encryptions +1
            else:
                counter_for_up_encryptions = counter_for_up_encryptions +1
            counter = counter + 1

        if counter_for_up_encryptions >0:
            print "My encrytors are still processing please wait until they finished, i will terminate in max 60 secs"
            time.sleep(5)
            counter_for_up_encryptions = 0
            counter = 0
            for a in encryptors:
                if len(a.get_work_in_progress()) == 0:
                    unresgister_rsp = a.unresgister_from_my_self()
                    if unresgister_rsp == True:
                        positions_for_delete.append(counter)
                    elif unresgister_rsp == "WORKING":
                        counter_for_up_encryptions = counter_for_up_encryptions +1
                else:
                    counter_for_up_encryptions = counter_for_up_encryptions +1
                counter = counter + 1
        else:
            print "No pending encryption and encrytors where notifyed"

        if automatic_distri != None:
            automatic_distri.terminate()
        #delete encrytors...
        #check if queue is empty before write
        if len(queue_to_encrypt) != 0 :            
            print "Writing queue to file ./pending_work.work..."
            with open("pending_work.work","w") as pending_work_file:
                for a in queue_to_encrypt:
                    pending_work_file.write(a+"\n")
        
        thread.start_new_thread(server.shutdown,())
        sys.exit(0)
def automatic_distribution(time_sleep):
        global queue_to_encrypt
        global encryptors
        global lock
        time.sleep(int(time_sleep))
        while True:
            print "automatic_distribution working..."
            distribute_queue(queue_to_encrypt,encryptors,lock)
            print "Ended automatic_distribution..."
            time.sleep(int(time_sleep))

if __name__ == "__main__":
    load_config()
    global loggers
    loggers=[]
    global encryptors
    encryptors=[]
    global queue_to_encrypt
    queue_to_encrypt=[]
    global server
    global lock
    lock = Lock()
    global automatic_distri
    automatic_distri = None
    #encrypt_in process are in objects from encryptors, in the queue are only the objects that are not distributed
    signal.signal(signal.SIGINT, signal_handler)
    HOST, PORT = configuration_file.get('General','msg_server_ip'), configuration_file.getint('General','msg_server_port')
    try:
        print "Reading ./pending_work.work..."
        with open("pending_work.work","r") as pending_work_file:
            for line in pending_work_file:
                queue_to_encrypt.append(line.rstrip())
            pending_work_file.truncate(0)
    except IOError:
        pass

    if configuration_file.getboolean('General','automatic_distri_queue'):
        print "Starting Automatic Queue Distribuing with time of %s..."%(configuration_file.getint('General','sleep_time_for_automatic_distri'))
        thread.start_new_thread(automatic_distribution,(configuration_file.getint('General','sleep_time_for_automatic_distri'),))
    print "Starting Message Server on {}:{}".format(HOST,PORT)
    # Create the server, binding to localhost on port 9999
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()
    print "Exiting..."