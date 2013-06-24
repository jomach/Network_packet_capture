#!/usr/bin/python
import ConfigParser

config = ConfigParser.RawConfigParser()

# When adding sections or items, add them in the reverse order of
# how you want them to be displayed in the actual file.
# In addition, please note that using RawConfigParser's and the raw
# mode of ConfigParser's respective set functions, you can assign
# non-string values to keys internally, but will receive an error
# when attempting to write to a file or when you get it in non-raw
# mode. SafeConfigParser does not allow such assignments to take place.
config.add_section('General')
config.add_section('Encrypt_server')
config.set('General', 'pubkey_location', '/install/daemonlogger-1.2.1/logger_settings/certificados/pubkey.key')
config.set('General', 'decrypt_files_location', '/install/decrypt/')
config.set('General', 'encrypted_files_location', '/install/encrypted/')
config.set('General', 'chunksize', '268435456')
config.set('General', 'db_host', 'localhost')
config.set('General', 'db_user', 'root')
config.set('General', 'db_passwd', 'toor')
config.set('General', 'db_name', 'http_logger')    
config.set('General', 'msg_server_ip', '10.0.0.2')    
config.set('General', 'msg_port', '9250')    
config.set('General', 'max_encryt_processes', '1000')    
config.set('Encrypt_server', 'encryp_server_port', '9260')    

# Writing our configuration file to 'example.cfg'
with open('logger.cfg', 'wb') as configfile:
    config.write(configfile)
print "I successfully created the config file"
