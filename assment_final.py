import select
import socket
import sys
import base64
import json
import zlib
import datetime
from datetime import timezone
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Random import get_random_bytes  
#Server function - which is responsible for receving the messages from client/user and also send the Ack/Nack messages
class ser:
    def server(serv,raw_pd):
        data = (conn.recv(1024)).decode()       
        if not data:  
            print("empty data")           
        else:  
            data1= json.loads(data) 
            decoded_data=eve().decode_message(data1['header']['msg_type'],data1)  
            if decoded_data['header']['msg_type']=='text':     
                print(decoded_data)   
                msg=eve()._ack('ack',raw_pd) 
                msg=(json.dumps(msg)).encode('utf-8')
                conn.sendall(msg)
            else:
                msg=(json.dumps(decoded_data)).encode('utf-8')
                conn.sendall(msg)              
class cli:
    def client(s,cli_pd):
        msg= eve()._text('text',cli_pd)
        msg1=(json.dumps(msg)).encode('utf-8')
        s.sendall(msg1)
        data=(s.recv(1024)).decode()
        print(data)
        if not data:
            print("no data closing")
            s.close()  
        return msg1              
class eve:    
    def _dh_1(self):
        print("hi we achived dh1")
    def _dh_2(self):
        print("hi we achived dh1")
    def _hello(self,message_type,pd):
        del pd['header']['crc'] 
        pd['header']['timestamp']=UTC_val 
        pd['header']['msg_type']=message_type   
        pd['body']='None'
        pd=eve.keygen(self,pd)
        pd=eve._crc(self,pd) 
        return pd
    def _chall(self):
        print("hi we achived dh1")
    def _resp(self):
        print("hi we achived dh1")     
    def _crc(self,pdu): 
        pdu_encoded=(json.dumps(pdu)).encode()
        crc=zlib.crc32(pdu_encoded)
        pdu['header']['crc']=crc
        secureDataLogging(pdu)
        return pdu
    def _text(self,message_type,txt_pd): 
        body = input("enter the  body/message")  
        txt_pd['header']['msg_type']=message_type
        txt_pd['header']['timestamp']=UTC_val 
        txt_pd['body']=body
        del txt_pd['header']['crc']
        txt_pd=eve.keygen(self,txt_pd)
        body= base64.b64encode(str(txt_pd['body']).encode()).decode()
        txt_pd['body']=body
        txt_pd=eve._crc(self,txt_pd)  
        return txt_pd   
    def _ack(self,message_type,pd):
        del pd['header']['crc']  
        pd['header']['msg_type']=message_type  
        pd['header']['timestamp']=UTC_val  
        pd['body']='None'
        pd=eve.keygen(self,pd)
        pd=eve._crc(self,pd) 
        return pd
    def _nack(self,message_type,pd):
        pd['header']['msg_type']=message_type   
        pd['header']['timestamp']=UTC_val 
        pd['body']='None'
        pd=eve.keygen(self,pd)
        pd=eve._crc(self,pd)
        return pd
    def decode_message(self,message_type,pdu):    
        print("the body is getting decoded")
        if message_type=='text':
            pdu_crc_val=pdu['header']['crc']
            print(pdu_crc_val)
            del pdu['header']['crc'] 
            pdu_encoded=(json.dumps(pdu)).encode('utf-8')
            crc=zlib.crc32(pdu_encoded)
            print(crc)
            body= (base64.b64decode(pdu['body'])).decode()        
            pdu['body']= body
            if pdu_crc_val==crc:
                print("validation check successful")
                pdu['header']['crc']=crc
                pdu['header']['timestamp']=UTC_val 
            else:
                print("validation check failed")    
                pdu=eve._nack(self,'nack',pdu)
            eve.decrypt(self,pdu)
            return pdu
    def keygen(self,pd):
        DHSK = b'abc'#get_random_bytes(32) # DH returns a fixed length shared secret of 32 byte
        user_secret=str(REMOTE_PASS).encode('utf-8')      
        print("keygen",user_secret)    
        hmac = HMAC.new(user_secret, DHSK, digestmod = SHA256)
        enc_key = hmac.digest() #Note we use the bytes object not the hex value for the key.
        hash = SHA256.new()
        hash.update(enc_key)
        iv = hash.digest()[:16] # The IV is a fixed length of 16 bytes. This notation fetchs bytes 0-15 (16 in total)[List slicing]
        hash.update(iv)
        hmac_key = hash.digest()
        hash.update(hmac_key)
        my_body=pd['body'] 
        data=str(my_body).encode('utf-8')
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)                 # Create new cipher
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))        # Encrypt the data
        ct_HMAC = HMAC.new(hmac_key, ct_bytes, digestmod = SHA256)  # Create new HMAC. Here we pass in the data directly
        ct_hash = ct_HMAC.digest()                                  # Get the bytes digest
        enhash=base64.b64encode(ct_hash).decode('utf-8')
        pd['security']['hmac']['val']=enhash
        return pd
    def decrypt(self,pd):
        DHSK = b'abc'#get_random_bytes(32) # DH returns a fixed length shared secret of 32 byte
        user_secret=str(LOCAL_PASS).encode('utf-8')    
        print("kdecrypet",user_secret)        
        hmac = HMAC.new(user_secret, DHSK, digestmod = SHA256)
        enc_key = hmac.digest() #Note we use the bytes object not the hex value for the key.
        hash = SHA256.new()
        hash.update(enc_key)
        iv = hash.digest()[:16] # The IV is a fixed length of 16 bytes. This notation fetchs bytes 0-15 (16 in total)[List slicing]
        hash.update(iv)
        hmac_key = hash.digest()
        hash.update(hmac_key)
        my_body=pd['body'] 
        data=str(my_body).encode('utf-8')
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)                 # Create new cipher
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))        # Encrypt the data
        ct_HMAC = HMAC.new(hmac_key, ct_bytes, digestmod = SHA256)  # Create new HMAC. Here we pass in the data directly
        ct_hash = ct_HMAC.digest()  
        decipher = AES.new(enc_key, AES.MODE_CBC, iv)               # Need a new decryption object
        pt = unpad(decipher.decrypt(ct_bytes), AES.block_size)      # Get the plain text
        print('       ct_text: ', pt)                                   
        verify_HMAC = HMAC.new(hmac_key, ct_bytes, digestmod = SHA256)  # New HMAC object
        try:
            verify_HMAC.verify(ct_hash)        # Verify excepts if there is an error. 
            print('       HMAC OK: True')
        except Exception as e:
            print(e) 
            print('       HMAC OK: False')
            pdu=eve._nack(self,'nack',pd)
            return pdu       
class secureDataLogging():
    def __init__(self,pd):
        with open('/Users/ashwinxaviourwilliam/Downloads/Assigment_info/std.log', 'a+') as f:
            if pd['header']['msg_type']=='text':
                f.write('Text message type:')
                f.write('\n')
            else:
                f.write('Acknowledge message type:')
                f.write('\n')
            f.write(json.dumps(pd))
            f.write('\n')
            f.write('\n')
            f.close()    
if __name__ == '__main__':
    with open('/Users/ashwinxaviourwilliam/Downloads/Assigment_info/directory.json','r') as f:
        abc=''.join(e.strip() for e in f)
    bcd=eval(abc)
    users=list(bcd) 
    UTC_val=datetime.datetime.now(timezone.utc).replace(tzinfo=timezone.utc).timestamp()
    usr=input("Please select which user")
    for i in range(0,4):
        for key,value in users[i].items():
            if value == usr:
                HOST = users[i]['ip']
                print("host", HOST)
                LOCAL_PORT = int(users[i]['port'])
                print("LOCAL_PORT", LOCAL_PORT)
                LOCAL_PASS = users[i]['password']
    usr1 =input("Please select the user you want from the contacts")
    for i in range(0,4):
        for key,value in users[i].items():
            if value == usr1:
                REMOTE_PORT = int(users[i]['port']) 
                print("REMOTE_PORT", REMOTE_PORT)
                REMOTE_PASS = users[i]['password']
    raw_pd = {'header': {'msg_type': '', 'crc':'','timestamp':''}, 'body':'','security':{'hmac': {'type': 'SHA256', 'val':''},'enc_type': 'AES256-CBC'}}
    raw_pd['header']['timestamp']=UTC_val
    server = socket.socket()
    server.bind((HOST, LOCAL_PORT))
    server.listen(1)  
    server.setblocking(False)
    inputs = [server, sys.stdin]
    outputs = []
    while True:
        readable, writeable, exceptional = select.select(inputs, [], [],25)  
        for r in readable:       
            if r is server:
                conn, addr = server.accept()
                inputs.append(conn)
            elif r is sys.stdin:
                client = socket.socket()
                client.connect((HOST, REMOTE_PORT))
                c=cli.client(client,raw_pd)       
            else:
                try:
                    s = ser.server(r,raw_pd)
                except socket.error as e:
                    inputs.remove(r)