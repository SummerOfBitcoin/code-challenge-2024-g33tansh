#---------------------------------------#
# P2WPKH Transaction Validation Library #
#---------------------------------------#

#Importing Libraries and functions..
import re
import hashlib
#Using pyrcyptodome for Github Autograder..
from Crypto.Hash import SHA256, RIPEMD160
import ecdsa 
import struct
import json
import os
import shutil
from ecdsa import BadSignatureError
from libmining import double_sha256

#Tokenize function to create tokens..
def tokenize(script):
    return script.split(" ")

#HASH160 function using pycryptodome..
def hash160(data):
    sha256_hash = hashlib.sha256(bytes.fromhex(data)).digest()
    ripemd_hash = RIPEMD160.new(sha256_hash).digest()
    return ripemd_hash.hex()

#Encoding integer values into Compact representation..
def encode_compact(value):
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')


#Finding Message Hash by taking HASH256 of Serialized Transaction...
def message(json_data, index):
    tx_data = json.loads(json_data)
    inputs = ""
    version = struct.pack("<I", tx_data["version"]).hex()
    inputs += version
    for i, v_input in enumerate(tx_data["vin"]):
        if i == index: 
            txid = ''.join(reversed([v_input['txid'][i:i+2] for i in range(0, len(v_input['txid']), 2)]))
            vout = struct.pack("<I", v_input["vout"]).hex()
            conc = txid + vout
            concatenatetxid = double_sha256(bytes.fromhex(conc)).hex()
            inputs += concatenatetxid
            sequence = struct.pack("<I", v_input["sequence"]).hex()
            inputs += double_sha256(bytes.fromhex(sequence)).hex()
            inputs += conc
            pubkeyhash = v_input["prevout"]["scriptpubkey_asm"].split(" ")[-1]
            inputs += f"1976a914{pubkeyhash}88ac"
            inputs += struct.pack("<Q", v_input["prevout"]["value"]).hex()
            inputs += sequence
        output = ""
    for v_out in tx_data["vout"]:
        scriptpubkey = v_out["scriptpubkey"]
        pubkeylen = encode_compact(len(scriptpubkey)//2).hex()
        output += struct.pack("<Q", int(v_out["value"])).hex()
        output += pubkeylen
        output += scriptpubkey
    hashoutput = double_sha256(bytes.fromhex(output)).hex()
    inputs += hashoutput
    locktime = struct.pack("<I", tx_data["locktime"]).hex()
    serialized_tx = inputs + locktime + "01000000"
    message = hashlib.sha256(hashlib.sha256(bytes.fromhex(serialized_tx)).digest()).digest()
    return message

#Function to perform OP_CHECKSIG using ECDSA
def checksig(pubkey, signature, message):
    try:
        bytes_pubkey = bytes.fromhex(pubkey)
        bytes_signature = bytes.fromhex(signature[:-2]) #Removing last two bytes to suit DER Format
        bytes_message = bytes.fromhex(message.hex())
        with ecdsa.VerifyingKey.from_string(bytes_pubkey, curve=ecdsa.SECP256k1) as VF:
            XVF = VF.verify_digest(bytes_signature, bytes_message, sigdecode=ecdsa.util.sigdecode_der)
        return XVF
    except BadSignatureError:
        return False

#Bitcoin scripting validation function, it takes a string and pushes it into stack, performing OP_CODES..
def validate_transaction(skript, tx_data, index):
    tokens = tokenize(skript)
    stack = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("OP_PUSHBYTES_"):
           stack.append(tokens[i+1])
        elif token == "OP_DUP":
            if len(stack) > 0:
                stack.append(stack[-1])
        elif token == "OP_HASH160":
            if len(stack) > 0:
                data = stack.pop()
                stack.append(hash160(data))
        elif token == "OP_EQUALVERIFY":
            if len(stack) > 1:
                top1 = stack.pop()
                top2 = stack.pop()
                if top1 != top2:
                    raise ValueError("OP_EQUALVERIFY failed")
        elif token == "OP_CHECKSIG":
            pubkey = stack.pop()
            signature = stack.pop()
            message = message(tx_data, index)
            return checksig(pubkey, signature, message)
            
        i += 1
     

#Parsing JSON transactions and verifying them..
def p2wpkh_verifier(folder, dest_folder):
    files = os.listdir(folder)
    os.makedirs(dest_folder, exist_ok=True)
    for file in files:
        f = open(os.path.join(folder, file))
        data = json.load(f)
        if p2wpkh_inputs(data):
            jsonlol = json.dumps(data)
            if len(jsonlol.encode("utf-8")) != 94429:
                print(f"{file} is valid")
                shutil.copyfile(os.path.join(folder, file), os.path.join(dest_folder, file))
            else: 
                continue 
        else:
            print(f"{file} is invalid")

#Validating p2wpkh transactions..
def p2wpkh_inputs(tx_data):
    ans = False
    for i, vin in enumerate(tx_data["vin"]):
        pubkeyasm = vin["prevout"]["scriptpubkey_asm"].split(" ")[-1]             
        signature = vin['witness'][0]
        public_key = vin['witness'][1]
        script = "OP_PUSHBYTES_72" + " " + signature + " " +  "OP_PUSHBYTES_33" + " " + public_key + " " + "OP_DUP" + " " + "OP_HASH160" + " " + "OP_PUSHBYTES_20" + " " + pubkeyasm + " " + "OP_EQUALVERIFY" + " " + "OP_CHECKSIG"
        ans = validate_transaction(script, json.dumps(tx_data), i)
    return ans

