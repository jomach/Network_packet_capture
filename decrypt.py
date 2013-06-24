#!/usr/bin/python
import sys
from Crypto.PublicKey import RSA
import ConfigParser, os
from Crypto.Cipher import PKCS1_v1_5
from encryptfunction import decrypt_file
from Crypto.Hash import SHA
from Crypto import Random

global private_key

global configuration_file

def get_cifered_random_bytes(file_to_decrypt,pri_key_RSA):
	
	private_cipher=PKCS1_v1_5.new(pri_key_RSA)
	random_bytes_file=open(file_to_decrypt,'rb')
	sentinel = Random.new()
	random_bytes=private_cipher.decrypt(random_bytes_file.read(),sentinel)
	random_bytes_file.close()
	return random_bytes
  
def load_config():
	
	#load and apply configs from file 
	try:
		global configuration_file
   	 	configuration_file = ConfigParser.RawConfigParser()
		configuration_file.read('./logger_settings/logger.cfg')
		#private_key_path =raw_input("Please enter the related("+config.get('General', 'pubkey_location')+") private RSA key:\n")     
		private_key_path ="/install/daemonlogger-1.2.1/logger_settings/certificados/private.key"
		global private_key
		private_key = RSA.importKey(open(private_key_path).read())
	except ConfigParser.NoSectionError:
		print "I cannot find the logger.cfg file. Make sure that is in ./logger_settings/logger.cfg, or the path to private key is not acessible"
		sys.exit(1)

def main(file_):
	load_config()
	global private_key
	key=get_cifered_random_bytes(file_to_decrypt=configuration_file.get('General', 'encrypted_files_location') +file_+".signature",pri_key_RSA=private_key)
	file2=configuration_file.get('General', 'encrypted_files_location')+file_+".enc" 
	decrypt_file(key=key,in_filename=file2 ,out_filename=configuration_file.get('General','decrypt_files_location')+file_,chunksize=configuration_file.getint('General','chunksize'))  
   

if __name__ == '__main__':		
		main(sys.argv[1])
		sys.exit()