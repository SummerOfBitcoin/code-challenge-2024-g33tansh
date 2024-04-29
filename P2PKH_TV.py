#--------------------------------------#
# P2PKH Transaction Validation Library #
#--------------------------------------#

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
def message_hash(json_data, index):
    tx_data = json.loads(json_data)
    inputs = ""
    version = struct.pack("<I", tx_data["version"]).hex()
    vin_length = encode_compact(len(tx_data["vin"])).hex()
    for i, v_input in enumerate(tx_data["vin"]):
        if i == index: 
            inputs += ''.join(reversed([v_input['txid'][i:i+2] for i in range(0, len(v_input['txid']), 2)]))
            inputs += struct.pack("<I", v_input["vout"]).hex()
            inputs += encode_compact(len(v_input["prevout"]["scriptpubkey"])//2).hex() 
            inputs += v_input["prevout"]["scriptpubkey"]
            inputs += struct.pack("<I", v_input["sequence"]).hex()
        else: 
            inputs += ''.join(reversed([v_input['txid'][i:i+2] for i in range(0, len(v_input['txid']), 2)]))
            inputs += struct.pack("<I", v_input["vout"]).hex()
            inputs += "00"
            inputs += ""
            inputs += struct.pack("<I", v_input["sequence"]).hex()
    inputs += encode_compact(len(tx_data["vout"])).hex()
    for output in tx_data["vout"]:
        inputs += struct.pack("<Q", int(output["value"])).hex()
        scriptpubkey = output["scriptpubkey"]
        inputs += encode_compact(len(scriptpubkey)//2).hex()
        inputs += output["scriptpubkey"]
    locktime = struct.pack("<I", tx_data["locktime"]).hex()
    serialized_tx = version + vin_length + inputs  + locktime + "01000000"
    #Hashing serialized_tx to find Message Hash..
    message = hashlib.sha256(hashlib.sha256(bytes.fromhex(serialized_tx)).digest()).digest()
    return message

#Function to perform OP_CHECKSIG using ECDSA
def checksig(pubkey, signature, message):
    try:
        bytes_pubkey = bytes.fromhex(pubkey)
        bytes_signature = bytes.fromhex(signature[:-2]) #Removing last two bytes to suit DER Format
        bytes_message = bytes.fromhex(message.hex())
        VF = ecdsa.VerifyingKey.from_string(bytes_pubkey, curve=ecdsa.SECP256k1)
        XVF = VF.verify_digest(bytes_signature, bytes_message, sigdecode=ecdsa.util.sigdecode_der)
        return XVF
    except BadSignatureError:
        return False

#Bitcoin scripting validation function, it takes a string and pushes it into stack, performing OP_CODES..
def script_validation(skript, tx_data, index):
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
            message = message_hash(tx_data, index)
            return checksig(pubkey, signature, message) 
        i += 1


#Parsing JSON transactions and verifying them..
def p2pkh_verifier(folder, dest_folder):
    files = os.listdir(folder)
    os.makedirs(dest_folder, exist_ok=True)
    for file in files:
        f = open(os.path.join(folder, file))
        data = json.load(f)
        if p2pkh_inputs(data):
            print(f"{file} is valid")
            shutil.copyfile(os.path.join(folder, file), os.path.join(dest_folder, file))
        else:
            print(f"{file} is invalid")

#Validating p2pkh transactions..
def p2pkh_inputs(tx_data):
    Ax = False
    for i, vin in enumerate(tx_data["vin"]):
        pubkeyasm = vin["prevout"]["scriptpubkey_asm"]
        scriptsigasm = vin["scriptsig_asm"]
        script = scriptsigasm + " " + pubkeyasm
        Ax = script_validation(script, json.dumps(tx_data), i)
    return Ax

