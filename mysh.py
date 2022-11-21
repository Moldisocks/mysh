'''
File: mysh.py
Project: mysh
Author: Moldisocks (moldisocks78@gmail.com)
-----
Last Modified: Monday, 21st November 2022
-----
Description: MyShell is a lightweight, SSH session manager.
-----
TO DO: 
    - Pin encrypted JSON de/serializer stores all session information.
'''


import base64
from configparser import ConfigParser
from getpass import getpass
import json
import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from uuid import uuid4
from dataclasses import dataclass,asdict

CONFIG_PATH = "config.ini"

@dataclass
class Session:
    name:str
    host:str
    user:str
    passwd:str
    keyEx:list = None
    ciphers:list = None
    port:int = 22
    id:str = str(uuid4())

    def __str__(self) -> str:
        return f"[{self.name}] - {self.user}@{self.host}{f':{self.port}' if self.port != 22 else ''}"

#Singleton
#Session Manager responsible for loading and saving config.
class SessionManager:
    __instance = None
    
    def __init__(self,path:str) -> None:
        if SessionManager.__instance != None:
            raise Exception("Cannot instantiate multiple session managers")
        else:
            SessionManager.__instance = self
            self._path = path
            self._sessions = []
            self._fernet = None
            self.__load_sessions()

    @staticmethod
    def getMgr(path):
        if SessionManager.__instance == None:
            SessionManager(path)
        return SessionManager.__instance
    
    def set_passcode(self,passcode:str):
            self.__salt()
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=self._salt,iterations=390000)
            key = base64.urlsafe_b64encode(kdf.derive(passcode.encode("utf-8")))
            self._fernet = Fernet(key)
            
    
    def __load_sessions(self):
        if os.path.exists(self._path):
            with open(self._path,"r") as f:
                for s in json.load(f):
                    self._sessions.append(Session(**s))

    @property
    def sessions(self)->list:
        return self._sessions

    def __salt(self):
        c = ConfigParser()
        c.read(CONFIG_PATH)
        if c.has_section("SECURITY"):
            salt = c.get("SECURITY","salt")
            self._salt = salt.encode("utf-8")
        else:
            self._salt = os.urandom(16)
            c.add_section("SECURITY")
            c.set("SECURITY","salt",str(self._salt))
            with open(CONFIG_PATH,"w") as f:
                c.write(f)
    
    def __decrypt_session(self,session:Session)-> Session:
        if (self._fernet):
            # session.user = self._fernet.decrypt(base64.b64decode(session.user)).decode("ascii")
            session.passwd= self._fernet.decrypt(base64.b64decode(session.passwd)).decode("ascii")
            return session
        else:
            raise Exception("Passcode not set! Cannot decrypt credentials")

    def __encrypt_session(self,session:Session)-> Session:
        if (self._fernet):
            # session.user = base64.b64encode(self._fernet.encrypt(session.user.encode("utf-8"))).decode("ascii")
            session.passwd= base64.b64encode(self._fernet.encrypt(session.passwd.encode("utf-8"))).decode("ascii")
            return session
        else:
            raise Exception("Passcode not set! Cannot encrypt credentials")

    def save_session(self,session:Session):          
        data = []
    
        if len(self._sessions):
            #Check if already exists
            existing_session:Session = None
            for s in self._sessions:
                if s.id == session.id:
                    existing_session = s
            if existing_session:
                self._sessions = [self.__encrypt_session(session) if s.id == session.id else s for s in self._sessions] #Overwrite if exists. Don't re-encrypt existing sessions.
            else:
                self._sessions.append(self.__encrypt_session(session))
            data = [asdict(s) for s in self._sessions]
        else:
            data = [asdict(self.__encrypt_session(session))]
        with open(self._path,"w") as f:
            json.dump(data,f)
    
    def start_session(self,id:str="",session:Session=None):
        if not session:
            for s in self._sessions:
                if s.id == id:
                    session = s
        if session:
            print(f"Starting: {session}")
            session = self.__decrypt_session(session)
            os.system(f"putty -ssh {session.host} -l {session.user} -pw {session.passwd}")
        else:
            print(f"Failed to find session with id: {id}")


def create_session()->Session:
    print("Create a new session.")
    user = input("User:")
    host = input("Host:")
    port = input("Port[22]:")
    if port:
        port = int(port)
    else:
        port = 22
    confirmed_passwd = ""
    attempts = 0
    while not confirmed_passwd: 
        passwd = getpass()
        confirm_passwd = getpass("Confirm password:")
        if passwd == confirm_passwd: 
            confirmed_passwd = passwd
        else:
            attempts += 1
            if attempts > 5:
                break
            print(f"Passwords don't match. Try again ({attempts})")
    name = f"{host}_{port}_{str(uuid4())[:-4]}"
    name = input("Name:")
    session = Session(name=name,host=host,port=port,user=user,passwd=confirmed_passwd)
    print(f"Ok. Here's your new session:\n\t{session}")
    return session


if __name__ == "__main__":
    mgr:SessionManager = SessionManager.getMgr("sessions.json")
    pc = getpass("Passcode:")
    if pc:
        mgr.set_passcode(pc)
        if len(sys.argv) > 1 and sys.argv[1] == "new":
            s =  create_session()
            mgr.save_session(s)
        else:
            selected = -1
            sessions = mgr.sessions
            while selected < 0:
                os.system("cls") if os.name == "nt" else os.system("clear")
                for i,s in enumerate(sessions):
                    print(f"[{i}] - {s}")
                
                choice = int(input(f"Select session (0-{len(sessions)-1})"))
                if 0 <= choice < len(sessions):
                    selected = choice
            mgr.start_session(session=sessions[selected])
        
