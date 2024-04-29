import re
import hashlib
from Crypto.Hash import SHA256, RIPEMD160
import ecdsa 
import struct
import json
import os
import shutil
from ecdsa import BadSignatureError
from libmining import double_sha256



def tokenize(script):
    return script.split(" ")

def hash160(data):
    sha256_hash = hashlib.sha256(bytes.fromhex(data)).digest()
    ripemd_hash = RIPEMD160.new(sha256_hash).digest()
    return ripemd_hash.hex()

def compact_size(value):
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')

def message_construction(json_data, index):


#preimage = version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence + hash256(outputs) + locktime    
    tx_data = json.loads(json_data)
    inputs = ""
    version = struct.pack("<I", tx_data["version"]).hex()
    #vin_length = compact_size(len(tx_data["vin"])).hex()
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
        pubkeylen = compact_size(len(scriptpubkey)//2).hex()
        output += struct.pack("<Q", int(v_out["value"])).hex()
        output += pubkeylen
        output += scriptpubkey
    hashoutput = double_sha256(bytes.fromhex(output)).hex()
    inputs += hashoutput
    locktime = struct.pack("<I", tx_data["locktime"]).hex()
    serialized_tx = inputs + locktime + "01000000"
    #print("Serialized Transaction:", serialized_tx)
    #print(serialized_tx)
    message = hashlib.sha256(hashlib.sha256(bytes.fromhex(serialized_tx)).digest()).digest()

    return message




def checksig(pubkey, signature, message):
    try:
        public_key_bytes = bytes.fromhex(pubkey)
        signature_bytes = bytes.fromhex(signature[:-2])
        message_bytes = bytes.fromhex(message.hex())
        
        # Create an ECDSA verifier
        vk = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)

        # Verify the signature
        is_valid = vk.verify_digest(signature_bytes, message_bytes, sigdecode=ecdsa.util.sigdecode_der)
        return is_valid
    except BadSignatureError:
        return False


def validate_transaction(combined_script, tx_data, index):
    tokens = tokenize(combined_script)

    # print("STACK", tokens)
    stack = []

    i = 0
    while i < len(tokens):
        token = tokens[i]

        if token.startswith("OP_PUSHBYTES_"):
           stack.append(tokens[i+1])

        elif token == "OP_DUP":
            if len(stack) > 0:
                stack.append(stack[-1])
            # print(f"Stack after OP_DUP: {stack}")

        elif token == "OP_HASH160":
            if len(stack) > 0:
                data = stack.pop()
                stack.append(hash160(data))
            # print(f"Stack after OP_HASH160: {stack}")

        elif token == "OP_EQUALVERIFY":
            if len(stack) > 1:
                top1 = stack.pop()
                top2 = stack.pop()
                # print(f"Comparing: {top1} == {top2}")
                if top1 != top2:
                    raise ValueError("OP_EQUALVERIFY failed")
                # print(f"Stack after OP_EQUALVERIFY: {stack}")
        elif token == "OP_CHECKSIG":
            pubkey = stack.pop()
            signature = stack.pop()
            message = message_construction(tx_data, index)
            return checksig(pubkey, signature, message)
            
        
 
        i += 1
        # print(stack)
    #return stack



def p2wpkh_verifier(folder, dest_folder):
    files = os.listdir(folder)
    os.makedirs(dest_folder, exist_ok=True)
    for file in files:
        f = open(os.path.join(folder, file))
        data = json.load(f)
        if valid_p2wpkh(data):
            jsonlol = json.dumps(data)
            if len(jsonlol.encode("utf-8")) != 94429:
            # print(file)
                shutil.copyfile(os.path.join(folder, file), os.path.join(dest_folder, file))
            else: 
                continue 
        else:
            print(f"{file} is invalid")

def valid_p2wpkh(tx_data):
    ans = False
    for i, vin in enumerate(tx_data["vin"]):
        pubkeyasm = vin["prevout"]["scriptpubkey_asm"].split(" ")[-1]             
        signature = vin['witness'][0]
        public_key = vin['witness'][1]
        #print(hash160(pubkeyasm))
        script = "OP_PUSHBYTES_72" + " " + signature + " " +  "OP_PUSHBYTES_33" + " " + public_key + " " + "OP_DUP" + " " + "OP_HASH160" + " " + "OP_PUSHBYTES_20" + " " + pubkeyasm + " " + "OP_EQUALVERIFY" + " " + "OP_CHECKSIG"
        #print(script)
        ans = validate_transaction(script, json.dumps(tx_data), i)
    return ans


in_folder = "./p2wpkh"
dest_folder = "./verified"
p2wpkh_verifier(in_folder, dest_folder)