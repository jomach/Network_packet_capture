class Log_server:
    name = None
    ip_adresse = None
    key = None

    def __init__(self,name,ip_adresse,key):
        self.name=name
        self.ip_adresse=ip_adresse
        self.key=key

    def __str__(self):
        return self.ip_adresse+":"+self.name


