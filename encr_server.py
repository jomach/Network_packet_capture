import SocketServer, ConfigParser, sys, signal, socket, os, sys, thread, time, MySQLdb
from multiprocessing import Pool, Lock
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5      
from encryptfunction import encrypt_file,decrypt_file
from Crypto.Hash import SHA
from Crypto.Cipher import AES
from Crypto import Random
from datetime import datetime


#Global Configurations
global configuration_file
configuration_file=None
global lock
lock = Lock()
global my_key
my_key = None
global my_processes_running
my_processes_running = 0
global max_processes_running
max_processes_running = 0
global work_in_progress
pool = None
global server

#this import need to be here because of the global variables !
def disk_manager(file_name):
    #global configuration_file
    #file_name = configuration_file.get('Encrypt_server','encrypted_files_location')+os.path.basename(file_name)
    configuration_file = load_config_localy()
    print "Start disk_manager at %s"%(datetime.now()) 
    space_needed=os.path.getsize(file_name)
    print "I need this Space: %s"%(space_needed) 
    conn = MySQLdb.connect(host=configuration_file.get('General','db_host'),user=configuration_file.get('General','db_user'),passwd=configuration_file.get('General','db_passwd'),db=configuration_file.get('General','db_name'))
    cursor = conn.cursor() 
    flag = True
    
    while(flag):
        print "I'm on the cycle from disk_manager for {}".format(file_name)
        disk = os.statvfs(configuration_file.get('Encrypt_server','encrypted_files_location'))
        available_space = ((disk.f_frsize * disk.f_bavail) / 1024) /1024
        space_needed = (space_needed / 1024 ) / 1024
                 
        if (available_space  < (space_needed + 1024)):
            print "Releasing space..."
            #need to clean up. delete file on db and file system
            #print "Cleanning up %s"%(file_name)
            cursor.execute(u'SELECT nome, data_entrada FROM web_logger_ficheiro WHERE locked = "0" ORDER by data_entrada asc limit 500')
            row = cursor.fetchone()
            if row is not None:
                file_name = row[0]
            else:
                #check if is space available in filesystem if not exit              
                if (available_space  < (space_needed + 1024)):
                    print "Something really bad happend, filesystem is full i think..\n "
                    sys.exit(-1)
            enc_file_to_rm = "%s.enc"%(os.path.basename(file_name))
            sign_file_to_rm = "%s.signature"%(os.path.basename(file_name))
            os.system('rm %s%s'%(configuration_file.get('Encrypt_server','encrypted_files_location'),enc_file_to_rm))
            os.system('rm %s%s'%(configuration_file.get('Encrypt_server','encrypted_files_location'),sign_file_to_rm))
            cursor.execute(u'DELETE from web_logger_ficheiro where nome="%s"'%(file_name))
 
        else:
            #Add a new meta-data in database
            date_today = "%s"%(datetime.now())
            date_today = date_today[:-7]
            file_name=os.path.basename(file_name)
            try:
                cursor.execute("""
                    INSERT INTO web_logger_ficheiro (nome, data_entrada, locked, size)
                    VALUES
                        ('%s','%s','%s','%s')
        
                    """%(file_name,date_today,0,space_needed))
            except Exception as e:
                #log exception !
                print "Panicccc line 64"
                print e 
                return False
                
            #print "I have space"
            flag = False              
    cursor.close()
    conn.close()
    print "Finish disk_manager at %s"%(datetime.now())
    
def save_meta_data(file_to_encrypt):
    pass 

def save_signature(KeyToSave,Public_Cipher,FileName):
    
    with open(FileName+".signature",'wb') as writefile:
        #ever time returns an 20 bytes long hash
        #h = SHA.new(writefile.read())
        writefile.write(KeyToSave)          
                           
def start_ciphering(file_to_encrypt):

    pubkey = RSA.importKey(open(configuration_file.get('Encrypt_server', 'pubkey_location')).read())
    random_bytes = os.urandom(32)
    #pid = os.fork()
    #if pid == 0 :
    disk_manager(file_name=file_to_encrypt)
    #sys.exit() 
    #encrypt file with 256MB chunks and 512Mb file size takes about 17 seconds
    print "Start cifer for %s at %s"%(file_to_encrypt, datetime.now()) 
    encrypt_file(key=random_bytes, in_filename=file_to_encrypt, out_filename=configuration_file.get('Encrypt_server','encrypted_files_location')+os.path.basename(file_to_encrypt+'.enc'), chunksize=configuration_file.getint('Encrypt_server','chunksize'))
    #cifer random key to post decrypt 
    public_cipher=PKCS1_v1_5.new(pubkey)
    ciphertext = public_cipher.encrypt(random_bytes)    
    #doing this on a fuction so i can perform saves on databases to (later on the project)
    save_signature(KeyToSave=ciphertext, Public_Cipher=public_cipher,FileName=configuration_file.get('Encrypt_server','encrypted_files_location')+os.path.basename(file_to_encrypt))
    print "Ended cifer for %s at %s\n"%(file_to_encrypt, datetime.now())
    os.system('rm %s'%(file_to_encrypt))
    return "DONE:%s"%(file_to_encrypt)

def check_if_logger_registed(logger, ip,loggers):    
    for a in loggers:
        if a.name == logger and a.ip_adresse == ip:
            return True
    return False

def do_the_work(ip_adresse, file_name, file_size):
    #load local confif
    configuration_file = load_config_localy()
    #need this variable because on msg if this name registed
    old_return_name = file_name
    file_name = os.path.basename(file_name)
    #get the file from logger
    if not configuration_file.getboolean('Encrypt_server','all_in_one'):
        #muss transfer the file to the server
        disk = os.statvfs(configuration_file.get('Encrypt_server','tmp_encry_location'))
        available_space = ((disk.f_frsize * disk.f_bavail) / 1024) /1024
        space_needed = (file_size / 1024 ) / 1024
        if space_needed + 100 < available_space:
            a =os.system("scp -B -q %s:%s %s"%(ip_adresse,file_name,configuration_file.get('Encrypt_server','tmp_encry_location')))
            if a !=0:
                print "PANIC I cannot get the remote file "
                return False
        else: 
            print "PANIC !! No File System  Reasonn : SPACE"
            return False
    else:
        #File already in server only need to move it from daemonlloger location to tmp encrypt location
        file_to_move = configuration_file.get('Encrypt_server','files_before_encrypt')+file_name
        #print "File to move : "+file_to_move
        #a = os.system("mv %s %s >/dev/null  2>&1"%(file_to_move,configuration_file.get('Encrypt_server','tmp_encry_location')))
        a = os.system("mv %s %s"%(file_to_move,configuration_file.get('Encrypt_server','tmp_encry_location')))
        if a != 0:
            
            return_str = "FILE_DOES_NOT_EXIST:%s:%s:%s"%(ip_adresse,old_return_name,file_size)
            print "PANIC !! I cannot move the file Return string is: %s"%(return_str)
            return return_str
    #File is now in tmp_location
    output = start_ciphering(configuration_file.get('Encrypt_server','tmp_encry_location')+file_name)
    #Request is like: 
            #   ENCRYPT:10.0.0.2:ficheiro1:5000
            #return from start_ciphering is like : DONE:<file_name>
    expected_output = "DONE:%s"%(configuration_file.get('Encrypt_server','tmp_encry_location')+file_name)
    if output == expected_output:
        return_str = "ENCRYPT:%s:%s:%s"%(ip_adresse,old_return_name,file_size)
        print "[info] EXTERN_PROCESS_WILL_RETURN_WORK_DONE: %s"%(return_str)
        return return_str
        
    else:
        print "EXTERN_PROCESS_FAILED!"
        return "FAILED"
    
def callback_function(self):
    global work_in_progress
    global my_processes_running
    global lock
    global my_key

    data = self.split(":")
    data_to_send = ""
    if data[0] == "FILE_DOES_NOT_EXIST":
        print "Call Back File does not exist"
        print data
        #a.remove_work("L:"+data_from_sender[3]+":"+data_from_sender[4]+":"+data_from_sender[5])
        data_to_send = "FILE_DOES_NOT_EXIST:"+my_key+":"+data[1]+":"+data[2]+":"+data[3]+"\n"
    
    if self == False or self == None or self =="":
        print "Something whent wrong with the extern process"
        return False

    if data[0] == "ENCRYPT":
        data_to_send = "DONE:"+my_key+":"+":".join(data)+"\n"
    #Sending information back to msg_server

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((configuration_file.get('General','msg_server_ip'), configuration_file.getint('General','msg_server_port')))
    except socket.error:
        print "Cannot connect to msg_server but work is done..."
    sock.sendall("HELLO"+"\n")
    received = sock.recv(1024)
    print "Data to send in Callback: %s"%(format(data_to_send))
    print "Free: %s"%(my_processes_running)
    sock.sendall(data_to_send)
    if sock.recv(1024) =="OK":
        #ENCRYPT:10.0.0.2:/log_ramdisk/daemonlogger.pcap.1346518553:1000
        lock.acquire()   
        try:

            work_in_progress.remove("ENCRYPT:"+data[1]+":"+data[2]+":"+data[3])
        except ValueError:
            print "ERROR on CALLBACK"
        finally:
            if my_processes_running >0:
                my_processes_running = my_processes_running - 1
            else:
                my_processes_running = 0
        lock.release()
        print "Response to msg_srv sended, work_in_progress: %s"%(work_in_progress)

def check_if_request_registed(request):    
    global work_in_progress
    a = work_in_progress.count(request)
    if a >0:
        return True
    else:
        return False

def stop_server():
    global pool
    global lock
    global my_processes_running
    global work_in_progress
    pool.close()
    lock.acquire()
    my_processes_running = max_processes_running + 1
    lock.release()
    if len(work_in_progress) ==0:
        server.shutdown()
        return True
    print "Waiting 30 seconds..."
    time.sleep(30)
    with open(configuration_file.get('Encrypt_server','file_for_work_in_progress'),'w') as work_in_progress_file:
        for a in work_in_progress:
            work_in_progress_file.write(a) 
    server.shutdown()
    sys.exit(0)



class MyTCPHandler(SocketServer.StreamRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    

    def handle(self):
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls
        global pool
        global max_processes_running
        global my_processes_running
        global work_in_progress
        
        try:

            self.data = self.rfile.readline().strip()
            if self.data =="HELLO":
                self.wfile.write("ENCRYPT_SRV")
                data_from_sender=self.rfile.readline().strip()
                if data_from_sender is "":
                    print "No data"
                    return False
                #Request is like: 
                #   ENCRYPT:10.0.0.2:ficheiro1:5000
                if check_if_request_registed(data_from_sender):
                    self.wfile.write("REQ_ALREADY_IN_QUEUE")
                    return False
                data_from_sender = data_from_sender.split(":")
                if  data_from_sender[0] == "ENCRYPT":

                    try:
                        socket.inet_aton(data_from_sender[1])
                        print "Before encry max_processes_running: %s"%(max_processes_running)
                        print "Before encry my_processes_running: %s"%(my_processes_running)
                        if max_processes_running > my_processes_running:
                            global lock
                            #Don't need now locking but if the server will go multithreaded them i will need it. 
                            lock.acquire()
                            my_processes_running = my_processes_running +1
                            print "Work in progress %s"%(work_in_progress)
                            work_in_progress.append(":".join(data_from_sender))
                            #def do_the_work(ip_adresse, file_name, file_size):
                            pool.apply_async(do_the_work, args = (data_from_sender[1],data_from_sender[2],data_from_sender[3],), callback = callback_function)
                            lock.release()
                            self.wfile.write("ENCRYPT_STARTED")
                        else:
                            print "Already Busy"
                            self.wfile.write("IAM_BUSY")
                        #Copy file (add the local installation or not...)
                        #Check I can run processes
                        # legal
                    except socket.error:
                        self.wfile.write("WRONG_IP")
                elif data_from_sender[0] =="UNREGISTER" and my_key == data_from_sender[1]:
                    print "Recived UNREGISTER"
                    self.wfile.write("OK")
                    thread.start_new_thread(stop_server,())
                    return

                else:
                    print "Wrong Header"
                    self.wfile.write("WRONG_HEADER")
                    return
        except IndexError:
            print "Index Error"
            self.wfile.write("WRONG_HEADER")

def load_config():
    
    #load and apply configs from file 
    try:
        global configuration_file
        configuration_file = ConfigParser.RawConfigParser()
        configuration_file.read('./encrsrv_settings/encrypt_srv.cfg')
    except ConfigParser.NoSectionError:
        print "I cannot find the encrypt_srv.cfg file. Make sure that is in ./encrsrv_settings/encrypt_srv.cfg"
        sys.exit()

def load_config_localy():
    #Loads the same configs as loadconfig but for the Processes
    #load and apply configs from file 
    configuration_file = None
    try:
        configuration_file = ConfigParser.RawConfigParser()
        configuration_file.read('./encrsrv_settings/encrypt_srv.cfg')
    except ConfigParser.NoSectionError:
        print "I cannot find the encrypt_srv.cfg file. Make sure that is in ./encrsrv_settings/encrypt_srv.cfg"
        sys.exit()
    return configuration_file

def signal_handler(signal, frame):
        print 'You pressed Ctrl+C!'
        global pool
        pool.close()
        global server
        server.server_close()
        

if __name__ == "__main__":
    load_config()
    global server
    global work_in_progress
    work_in_progress = []
    max_processes_running = configuration_file.getint('Encrypt_server','max_processes')
    pool = Pool(processes=max_processes_running)
    signal.signal(signal.SIGINT, signal_handler)
    print "Starting...\n"
    try:

        with open(configuration_file.get('Encrypt_server','file_for_work_in_progress'),'w') as work_in_progress_file:
            for a in work_in_progress_file:
                work_in_progress.append(a)
            work_in_progress_file.truncate(0)
    except IOError:
        pass

    print "Registing this encry_server on msg_server(%s)... "%(configuration_file.get('General','msg_server_ip'))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        # Connect to server and send data
        sock.connect((configuration_file.get('General','msg_server_ip'), configuration_file.getint('General','msg_server_port')))
        sock.sendall("HELLO"+"\n")
        # Receive data from the server and shut down
        received = sock.recv(1024)
        if received[:7] == "MSG_SRV":
            print "MSG_SRV ok !"
        else:
            print "Sorry Wrong response"
            sys.exit(-1)

        data = "REGISTER:E:%s:%s:%s\n"%(socket.gethostname(),configuration_file.get('Encrypt_server','encryp_server_port'),configuration_file.get('Encrypt_server','max_processes'))
        print data
        sock.sendall(data)
        received = sock.recv(1024)
        received = received.split(":")
        if received [0] == socket.gethostname() and received[1]=="REGISTED" and received[2]=="E":
            print "{} sucessefull registed on Message Server".format(socket.gethostname())
            my_key = received[3]
        elif received[1] == "ALREADY_REGISTED":
            print "Already Registed, moving on..."
        else:
            print "Sorry I cannot register in Message Server...\n Quitting !"
            sys.exit(-1)
    finally:
        sock.close()
    signal.signal(signal.SIGINT, signal_handler)
    HOST, PORT = configuration_file.get('Encrypt_server','encryp_server_ip'), configuration_file.getint('Encrypt_server','encryp_server_port')

    # Create the server, binding to localhost on port 9999
    
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)
    print "Starting Encrpyt Server on {}:{}".format(HOST,PORT)
    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()
    print "Exiting..."
