import urllib2
import os
import base64
import json
import binascii
import Crypto
import requests
import hashlib
import sys
import textwrap
from flask import Flask, render_template, request, make_response, url_for, redirect
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from random import randint
from Crypto.Hash import SHA
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from M2Crypto import DSA, BIO
from pyasn1.type import univ
from pyasn1.codec.ber import encoder, decoder
from Crypto import Random


app = Flask(__name__)
BLOCK_SIZE = 16
SERVER = "http://jmessage.server.isi.jhu.edu/"
PATH = "registerKey/"
PATH_lookup = "lookupKey/"
PATH_sendmsg = "sendMessage/"
PATH_getmsg = "getMessages/"
PATH_enum = "lookupUsers"
global rsa
global rsa_pub
global dsa
global dsa_pub

def pkcs5_pad(s):
   return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def pkcs5_unpad(s):
   return s[0:-ord(s[-1])]

@app.route("/regkeys")
def register_key():
   load_keys()
   usrname = request.cookies.get('username', None)
   #resp = make_response(render_template('regkeys.html', 200))
   data = {}
   temprsa = rsa_pub.replace('-----BEGIN PUBLIC KEY-----\n','')
   temprsa = temprsa.replace('\n-----END PUBLIC KEY-----','')
   temprsa = temprsa.replace('\n','')
   tempdsa = dsa_pub.replace('-----BEGIN PUBLIC KEY-----\n','')
   tempdsa = tempdsa.replace('\n-----END PUBLIC KEY-----','')
   tempdsa = tempdsa.replace('\n','')

   data['keyData'] = temprsa +"%"+ tempdsa
   header = {'content-type': 'application/json'}
   res = requests.post(SERVER + PATH + usrname, data=json.dumps(data),headers=header)
   return "Keys registered! <a href='http://jmessage.server.isi.jhu.edu/lookupKey/"+usrname+"'>Check Here!</a>"

def key_lookup(usrname):

   url = SERVER + PATH_lookup + usrname
   content = urllib2.urlopen(url).read()
   content = json.loads(content)
   data = content["keyData"]
   rsa_encoded = data.split('%')[0]
   dsa_encoded = data.split('%')[1]

   return rsa_encoded, dsa_encoded

def get_message(usrname):

   url = SERVER + PATH_getmsg + usrname
   content = urllib2.urlopen(url).read()
   content = json.loads(content)
   return content


def send_message(message, user_rec, usrname):
   url = SERVER + PATH_sendmsg + usrname
   msg_id = randint(100000,999999)
   data = {}
   data['recipient'] = user_rec
   data['messageID'] = msg_id
   data['message'] = message
   header = {'content-type': 'application/json'}
   res = requests.post(url, data=json.dumps(data),headers=header)
   print res.text

def do_crc(crctemp):
  temp = crctemp & 0xffffffff
  return ('%08X' % temp)

# Encryption and Message Formatting

@app.route("/encrypt", methods=['POST'])

def encrypt():

  load_keys()
  usrname = request.cookies.get('username', None)
  user_rec = request.form['recepient']
  rsa_rec, dsa_rec = key_lookup(user_rec)
  message = request.form['message']
   
  app_message = usrname+"3A".decode('hex')+message.encode('utf8')
  crc = binascii.crc32(app_message)
  mcrc = app_message.encode('hex') + do_crc(crc)
  mcrc = binascii.unhexlify(mcrc)
  mpadded = pkcs5_pad(mcrc)

  #AES CTR encryption
  aes_key = os.urandom(16)
  iv = os.urandom(16)
  backend = default_backend()
  cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=backend)
  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(mpadded) + encryptor.finalize()
  prepend_cipher = iv + ciphertext

  #RSA encryption
  rsa_rec = base64.b64decode(rsa_rec)
  rec_pub = RSA.importKey(rsa_rec)
  pkcs = PKCS1_v1_5.new(rec_pub)
  enc_key = pkcs.encrypt(aes_key)
  
  enc_key_b64=base64.b64encode(enc_key)
  ciphertext_b64=base64.b64encode(prepend_cipher)
  output = enc_key_b64+"20".decode('hex')+ciphertext_b64
  #outputtemp=output.encode('utf8')
  dsa_me = DSA.load_key('dsa.key')
  some = SHA.new()
  some.update(output)

  dsa_sign = dsa_me.sign_asn1(some.digest())
  dsa_sign_64 = base64.b64encode(str(dsa_sign))
  cipher_out = output + "20".decode('hex') + dsa_sign_64
  send_message(cipher_out,user_rec, usrname)
  return "Message sent! <a href='http://jmessage.server.isi.jhu.edu/getMessages/"+user_rec+"'>Check Here!</a>"

@app.route("/decrypt", methods=['GET'])

def decrypt():

  load_keys()
  usrname = request.cookies.get('username', None)
  content = get_message(usrname)
  msg_out = ""
  for entry in content['messages']:
    cipher = entry['message']
    senderID = entry['senderID']
 
    rsa_user, dsa_rec = key_lookup(senderID)
    cipher_out = cipher.split(" ")
    enc_key = base64.b64decode(cipher_out[0])
    ciphertext = base64.b64decode(cipher_out[1])
    dsa_sign = base64.b64decode(cipher_out[2])
    cipher_o = ' '.join(cipher_out[0:2])
    cipher_o = cipher_o.encode('utf8')
    dsa_rec = "-----BEGIN PUBLIC KEY-----\n" + '\n'.join(textwrap.wrap(dsa_rec, 64)) + "\n-----END PUBLIC KEY-----"
    with open('dsa_rec_pub.key','w') as f:
      f.write(dsa_rec)
    some = SHA.new()
    some.update(cipher_o)
    dsa_re = DSA.load_pub_key('dsa_rec_pub.key')
    if dsa_re.verify_asn1(some.digest(), dsa_sign):
      print ""
    else:
      sys.exit()
    rsa_priv = RSA.importKey(rsa)
    pkcs = PKCS1_v1_5.new(rsa_priv)
    dsize = SHA.digest_size
    sentinel = Random.new().read(15 + dsize)
    aes_key = pkcs.decrypt(enc_key, sentinel)
    iv = ciphertext[0:16]

    #AES CTR decryption
    backend = default_backend()
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=backend)
    decryptor = cipher.decryptor()
    mcrc = decryptor.update(ciphertext[16:])
    mcrc = pkcs5_unpad(mcrc)
    mcrc_hex = mcrc.encode('hex')
    crc = mcrc_hex[-8:]
    app_message = mcrc_hex[0:len(mcrc_hex)-8].decode('hex')

    sender = app_message.split(":")[0]
    message = app_message.split(":")[1]
    new_crc = binascii.crc32(app_message)
    new_crc = binascii.unhexlify(do_crc(new_crc))
    if crc.decode('hex') != new_crc:
      continue
    if sender != senderID:
      continue
    msg_out = msg_out + senderID + " : " + message + "<br/><br/>"
  return msg_out

@app.route("/enumusers", methods=['GET'])
def enumusers():

  url = SERVER + PATH_enum
  content = urllib2.urlopen(url).read()
  content = json.loads(content)
  i=0
  users=""
  for entry in content['users']:
    users = users + content['users'][i] + "<br/>"
    i=i+1

  #  print entry    
  return users

@app.route("/fingerprint",  methods=['POST'])
def fingerprint():

  user_rec = request.form['recepient']
  rsa_rec, dsa_rec = key_lookup(user_rec)   
  data = rsa_rec +"%"+ dsa_rec
  fingerprint = data.encode('utf8')
  return hashlib.sha256(fingerprint).hexdigest()

@app.route("/keygen")
def key_generation():

  #DSA key generation

  dsa = DSA.gen_params(1024)
  dsa.gen_key()
  dsa.save_key('dsa.key', None)
  dsa.save_pub_key('dsa_pub.key')

  #RSA key generation

  new_key = RSA.generate(1024)
  public_key = new_key.publickey().exportKey("PEM")
  private_key = new_key.exportKey("PEM")
  with open('rsa_pub.key','w') as f:
    f.write(public_key)
  with open('rsa.key','w') as f:
    f.write(private_key)
  return "Key generated!"

def load_keys():

  global rsa
  global rsa_pub
  global dsa
  global dsa_pub

  with open('rsa.key','r') as f:
    rsa_content = f.read()
  rsa = rsa_content.strip()

  with open('rsa_pub.key','r') as f:
    rsa_pub_content = f.read()
  rsa_pub = rsa_pub_content.strip()

  with open('dsa.key','r') as f:
    dsa_content = f.read()
  dsa = dsa_content.strip()

  with open('dsa_pub.key','r') as f:
    dsa_pub_content = f.read()
  dsa_pub = dsa_pub_content.strip()


@app.route('/menu', methods=['GET','POST'])
def menu():
  usrname = request.cookies.get('username', None) or request.form['username']   
  resp = make_response(render_template('menu.html'), 200)
  resp.set_cookie('username', usrname)
  return resp 
@app.route('/') 

def root():
  if request.cookies.get('usrname'):
    return redirect(url_for('menu'))
  else:
    return render_template('enter.html')


if __name__ == "__main__":
    # Doesn't work for some reason unless you run as root, so remember to sudo
    app.run(host='0.0.0.0', port=5000)
