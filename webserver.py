import http.server
import requests
import socketserver
import json
import hmac
import hashlib
import base64
import time
from urllib.parse import urlparse
from urllib.parse import parse_qs
from Crypto.Cipher import AES
from socketserver import ThreadingMixIn
import threading
from concurrent.futures import ThreadPoolExecutor # pip install futures

## App parameters
PORT = 10280
SRV_IP = "192.168.68.102" ## IP address of this server

## global vars
seq = 0
appiv = ""
rnd_1 = ""
rnd_2 = "a5rLvXXkl7CAH6db"  ## some random string
time_1 = ""
time_2 = "446005717073803"  ## some random long int
lankey = ""
appCryptoKey = ""
appSignKey = ""
appIvSeed = ""
devCryptoKey = ""
devIvSeed = ""
data = "{\"seq_no\":"+str(seq)+",\"data\":{}}"
seq=0
laststatus = '<meta http-equiv="refresh" content="5">'
DSN = "" ## (unique???) DSN of the coffee machine 
DEV_IP = "" ## IP address on the coffee machine

def hmacForKeyAndData(key, data):
    # print(key,data)
    mac_hash = hmac.new(key, data, hashlib.sha256)
    return mac_hash.digest()
    
## AES tools
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * b'\x00'
unpad = lambda s: s[:s.find(b'\x00')]

## Bitwise split
def extract_bits(number, k, p):
    strhex = number.hex()
    return bytearray.fromhex(strhex[k:p])
    
    
def AESencrypt(message, key, iv):
        message = message.encode()
        raw = pad(message)
        # print(raw)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc = cipher.encrypt(raw)
        return base64.b64encode(enc).decode('utf-8')

def AESdecrypt(enc, key, iv):
    enc = base64.b64decode(enc)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(enc)
    return unpad(dec)

## Generate keys based on first exchanges
def initCrypto():
    global appiv,rnd_1,rnd_2,time_1,time_2,appCryptoKey,appSignKey,appIvSeed,devCryptoKey,devIvSeed,seq
    with open('keys.json', 'r') as openfile:
    # Reading from json file
        json_object = json.load(openfile)
    openfile.close()
    # print(json_object)
    rnd_1 = json_object['rnd_1']
    time_1 = json_object['time_1']
   
    rnd_1s = rnd_1.encode('utf-8')
    rnd_2s = rnd_2.encode('utf-8')
    time_1s = time_1.encode('utf-8')
    time_2s = time_2.encode('utf-8')
    lankeys = lankey.encode('utf-8')

    # print(rnd_1,rnd_2)
    lastbyte = b"\x30"
    concat = rnd_1s  + rnd_2s  + time_1s  + time_2s  + lastbyte
    # print(concat)
    appSignKey = hmacForKeyAndData(lankeys ,hmacForKeyAndData(lankeys ,concat) + concat)
    lastbyte = b"\x31"
    concat = rnd_1s  + rnd_2s  + time_1s  + time_2s  + lastbyte
    # print(concat)
    appCryptoKey = hmacForKeyAndData(lankeys ,hmacForKeyAndData(lankeys ,concat) + concat )
    lastbyte = b"\x32"
    concat = rnd_1s  + rnd_2s  + time_1s  + time_2s  + lastbyte
    # print(concat)
    appIvSeed = extract_bits(hmacForKeyAndData(lankeys ,hmacForKeyAndData(lankeys ,concat) + concat ),0,16*2)
    print("appCryptoKey:",base64.b64encode(appCryptoKey),"appIvSeed:",base64.b64encode(appIvSeed))

    lastbyte = b"\x31"
    concat = rnd_2s  + rnd_1s  + time_2s  + time_1s  + lastbyte
    # print(concat)
    devCryptoKey = hmacForKeyAndData(lankeys ,hmacForKeyAndData(lankeys ,concat) + concat )
    lastbyte = b"\x32"
    concat = rnd_2s  + rnd_1s  + time_2s  + time_1s  + lastbyte
    # print(concat)
    devIvSeed = extract_bits(hmacForKeyAndData(lankeys ,hmacForKeyAndData(lankeys ,concat) + concat ),0,16*2)
    print("devCryptoKey:",base64.b64encode(devCryptoKey),"devIvSeed:",base64.b64encode(devIvSeed))


## Get Access token used to send requests to the Ayla servers
def get_access_token(refresh_token=""):
    api_url = "https://user-field-eu.aylanetworks.com/users/refresh_token.json"
    headers =  {"Content-Type":"application/json"}
    json = {"user":{"refresh_token":refresh_token}}
    response = requests.post(api_url, headers=headers, json=json)
    print(response.json())

    if response.status_code == 200:
        access_token = response.json()['access_token']
        refresh_token = response.json()['refresh_token']
        # print("access:",access_token)
    else:
        # print(response.json())
        refresh_token = get_app_token()
        access_token = get_access_token(refresh_token)
    # save refresh token
    f = open("token.txt", "w")
    f.write(refresh_token)
    f.close()
    # print("refresh:",refresh_token)
    return access_token
    
## Connect to Delonghi's IDP (used only during 1st connection)    
def get_app_token():
    ## login with IDP
    print("https://fidm.eu1.gigya.com/oidc/op/v1.0/3_e5qn7USZK-QtsIso1wCelqUKAK_IVEsYshRIssQ-X-k55haiZXmKWDHDRul2e5Y2/authorize?client_id=1S8q1WJEs-emOB43Z0-66WnL&response_type=code&redirect_uri=https://google.it&scope=openid%20email%20profile%20UID%20coffee&nonce=1707250274134")
    print('Paste the callback URL:')
    url = input()
    parsed_url = urlparse(url)
    code = parse_qs(parsed_url.query)['code'][0]

    print(code)

    ## get IDP access token
    api_url = "https://fidm.eu1.gigya.com/oidc/op/v1.0/3_e5qn7USZK-QtsIso1wCelqUKAK_IVEsYshRIssQ-X-k55haiZXmKWDHDRul2e5Y2/token"
    params = {"code": code,"grant_type" : "authorization_code", "redirect_uri" : "https://google.it"}
    headers =  {"Authorization":"Basic MVM4cTFXSkVzLWVtT0I0M1owLTY2V25MOmxtbmNlaUQwQi00S1BOTjVaUzZXdVdVNzBqOVY1QkN1U2x6Mk9Qc3ZIa3lMcnloTWtKa1B2S3NpdmZUcTNSZk5ZajhHcENFTHRPQnZoYURJektjQnRn"}
    response = requests.post(api_url, params=params, headers=headers).json()
    # print(response)
    token = response['access_token']


    ## Exchange IDP token for Ayla token

    api_url = "https://user-field-eu.aylanetworks.com/api/v1/token_sign_in"
    params = {"app_id":"DeLonghiCoffeeLink2-DQ-id","app_secret":"DeLonghiCoffeeLink2-2BE_5vrnT4nbx1eE4yuTYo8gPSA", "token" : token}
    response = requests.post(api_url, params=params).json()
    refresh_token = response['refresh_token']
    # print(refresh_token)
    return refresh_token

def get_lankey(access_token):
    global DSN
    ## get LAN key used for encrypting local trafic
    api_url = "https://ads-eu.aylanetworks.com/apiv1/devices/"+DSN+"/connection_config.json"
    headers =  {"Authorization":"auth_token "+access_token}
    data = requests.get(api_url, headers=headers)
    print("lankey:",data.headers,data.text)
    response = data.json()
    local_key_id = response['local_key_id']
    local_key = response['local_key']
    # print("lan key:", local_key_id,local_key)
    return local_key

def get_status(access_token):
    ## get machine status
    api_url = "https://ads-eu.aylanetworks.com/apiv1/devices.json"
    headers =  {"Authorization":"auth_token "+access_token}
    response = requests.get(api_url, headers=headers).json()
    print(response[0]['device'])
    return response[0]['device']

def put_request():
    global DEV_IP,SRV_IP,PORT
    ## get machine status
    api_url = "http://"+DEV_IP+"/local_reg.json"
    headers =  {"Content-Type":"application/json"}
    json = {"local_reg":{"ip":SRV_IP,"notify":1,"port":PORT,"uri":"/local_lan"}}
    response = requests.put(api_url, headers=headers, json=json)
    print(response)

class myHandler(http.server.SimpleHTTPRequestHandler):

    ## Handler for POST requests
    def do_POST(self):
        global appiv,rnd_1,rnd_2,time_1,time_2,appCryptoKey,appSignKey,appIvSeed,devCryptoKey,devIvSeed,seq,laststatus
        file = self.path.split('?')[0]
        print(file)
        #default
        code = 404
        response = "Not Found"
        header = "application/json"
        ## key_exchange: 1st communication, in clear, used to exchange salts for encrypting following trafic
        if file == "/local_lan/key_exchange.json":
            seq = 0
            self.data_string = self.rfile.read(int(self.headers['Content-Length']))
            data = json.loads(self.data_string.decode('utf-8'))
            rnd_1 = data['key_exchange']['random_1']
            time_1 = str(data['key_exchange']['time_1'])
            # print(rnd_1,time_1)
            # save keys localy
            with open("keys.json", "w") as outfile:
                json.dump({"rnd_1":rnd_1,"time_1":time_1},outfile)
            outfile.close()
            code = 202
            header = "application/json"
            initCrypto()
            response = {"random_2":rnd_2,"time_2":int(time_2)}
            laststatus = '<meta http-equiv="refresh" content="5"><pre>Initiating encryption:\nappCryptoKey:{}, appIvSeed:{}\ndevCryptoKey:{}, devIvSeed{}</pre>'.format(base64.b64encode(appCryptoKey).decode('utf-8'),base64.b64encode(appIvSeed).decode('utf-8'),base64.b64encode(devCryptoKey).decode('utf-8'),base64.b64encode(devIvSeed).decode('utf-8')) 
        
        ## Read data returned by the machine
        if file == "/local_lan/property/datapoint.json":
            seq = 0
            self.data_string = self.rfile.read(int(self.headers['Content-Length']))
            data = json.loads(self.data_string.decode('utf-8'))
            dec = AESdecrypt(data['enc'], devCryptoKey, devIvSeed)
            devIvSeed = bytearray.fromhex(base64.b64decode(data['enc']).hex()[-32:])
            print(dec)
            try:
                ## decode fails sometimes (incomplete message ???) because of wrong IV. In that case, don't send response and wait for message beeing resent
                decoded = json.loads(dec.decode('utf-8'))
                # print(decoded)
                monitor = base64.b64decode(decoded['data']['value'])
                name = decoded['data']['name']
                laststatus = '<meta http-equiv="refresh" content="5"><pre>property:{}\nvalue:{}</pre>'.format(name,decoded['data']['value'])
                ## log message
                with open('logs.txt', 'a') as logfile:
                    logfile.write('{}:{}\n'.format(name,decoded['data']['value']))
                    logfile.close()
                print("switch", bin(monitor[5] + (monitor[6] << 8)))
                print("alarm", bin(monitor[7] + (monitor[8] << 8) + (monitor[12] << 16) + (monitor[13] << 24)))
                code = 200
            except:
                code = 0
            header = "application/json"
            response = ""
        if code:    
            #send response
            self.send_response(code)
            self.send_header("Content-type", header)
            self.end_headers()
            #content
            self.wfile.write(json.dumps(response).encode('utf-8'))

    ## Handler for GET requests
    def do_GET(self):
        global appiv,rnd_1,rnd_2,time_1,time_2,appCryptoKey,appSignKey,appIvSeed,devCryptoKey,devIvSeed,seq,data,DSN,laststatus
        file = self.path.split('?')[0]
        print(file)
        #default
        code = 404
        response = "Not Found"
        header = "application/json"
        ## frontend
        if file == "/index.html" or file == "/css/style.css" :
            code = 200
            self.path = file
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        if file == "/status":
            header = "text/html"
            response = laststatus
            code = 200
        ## Receive commands to be sent
        if file == "/turn_on":
            timestamp = bytearray.fromhex(hex(int(time.time()))[2:])
            signal = bytearray.fromhex('0d07840f02015512')
            value = base64.b64encode(signal+timestamp).decode('utf-8')
            data = "{\"seq_no\":"+str(seq)+",\"data\":"+'{"properties":[{"property":{"base_type":"string","dsn":"'+DSN+'","name":"data_request","value":"'+value+'\n"}}]}}'
            put_request()
            code = 200
            response = ""
        if file == "/get_monitor":
            data = "{\"seq_no\":"+str(seq)+",\"data\":"+'{"cmds":[{"cmd":{"cmd_id":1,"data":"","method":"GET","resource":"property.json?name=d302_monitor","uri":"/local_lan/property/datapoint.json"}}]}}'
            put_request()
            code = 200
            response = ""
        if file == "/get_properties":
            arg = self.path.split('?')[1].split('=')[1]
            data = "{\"seq_no\":"+str(seq)+",\"data\":"+'{"cmds":[{"cmd":{"cmd_id":1,"data":"","method":"GET","resource":"property.json?name='+arg+'","uri":"/local_lan/property/datapoint.json"}}]}}'
            put_request()
            code = 200
            response = ""
        
        ## Send the machine the next command to execute
        if file == "/local_lan/commands.json":
            self.data_string = self.rfile.read(int(self.headers['Content-Length']))
            code = 200
            header = "application/json"
            seq=seq+1
            if appCryptoKey != "":
                enc = AESencrypt(data, appCryptoKey, appIvSeed)
                ## prepare IV for next decryption
                appIvSeed = bytearray.fromhex(base64.b64decode(enc).hex()[-32:])
                # print("next_iv:",base64.b64encode(appIvSeed))
            
                sign = base64.b64encode(hmacForKeyAndData(appSignKey,data.encode('utf-8'))).decode('utf-8')
                ## reset data to default
                data = "{\"seq_no\":"+str(seq)+",\"data\":{}}"
                response = "{\"enc\":\""+enc+"\",\"sign\":\""+sign+"\"}"
                # print(response)
            
        #response code
        self.send_response(code)
        #headers
        self.send_header("Content-type", header)
        self.end_headers()
        #content
        self.wfile.write(response.encode("utf-8"))

class PoolMixIn(ThreadingMixIn):
    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)
 
Handler = myHandler
Handler.extensions_map={
    '.manifest': 'text/cache-manifest',
    '.html': 'text/html',
    '.png': 'image/png',
    '.jpg': 'image/jpg',
    '.svg':    'image/svg+xml',
    '.css':    'text/css',
    '.js':    'application/x-javascript',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '': 'application/octet-stream', # Default
} 

def run():
    class PoolHTTPServer(PoolMixIn, http.server.HTTPServer):
        pool = ThreadPoolExecutor(max_workers=40)
    server = PoolHTTPServer(('0.0.0.0', PORT), Handler)
    print("connect to http://127.0.0.1:"+str(PORT)+"/index.html")
    server.serve_forever()

## get saved token and refresh it:
try:
    f = open("token.txt", "r")
    refresh_token = f.read() 
    f.close()
    access_token = get_access_token(refresh_token)
except:
    access_token = get_access_token()

## Retrieve DSN and LAN key from the cloud
status = get_status(access_token)
DSN = status['dsn']
DEV_IP = status['lan_ip']
lankey = get_lankey(access_token)

## Run web server
if __name__ == '__main__':
    run()
