import re
import hashlib
from Crypto.Hash import SHA256, RIPEMD160
import ecdsa 
import struct
import json
import os
import shutil
from ecdsa import BadSignatureError
from mine import double_sha256

def tokenize(script):
    return script.split(" ")

def hash160(data):
    sha256_hash = hashlib.sha256(bytes.fromhex(data)).digest()
    ripemd_hash = RIPEMD160.new(sha256_hash).digest()
    return ripemd_hash.hex()

def compact(value):
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')

def message_construction(json_data, index):
    
    tx_data = json.loads(json_data)
    inputs = ""
    version = struct.pack("<I", tx_data["version"]).hex()
    vin_length = compact(len(tx_data["vin"])).hex()
    

    for i, v_input in enumerate(tx_data["vin"]):
        if i == index: 
            inputs += ''.join(reversed([v_input['txid'][i:i+2] for i in range(0, len(v_input['txid']), 2)]))
            inputs += struct.pack("<I", v_input["vout"]).hex()
            inputs += compact(len(v_input["prevout"]["scriptpubkey"])//2).hex() 
            inputs += v_input["prevout"]["scriptpubkey"]
            inputs += struct.pack("<I", v_input["sequence"]).hex()
        else: 
            inputs += ''.join(reversed([v_input['txid'][i:i+2] for i in range(0, len(v_input['txid']), 2)]))
            inputs += struct.pack("<I", v_input["vout"]).hex()
            inputs += "00"
            inputs += ""
            inputs += struct.pack("<I", v_input["sequence"]).hex()
    inputs += compact(len(tx_data["vout"])).hex()
    for output in tx_data["vout"]:
        inputs += struct.pack("<Q", int(output["value"])).hex()
        scriptpubkey = output["scriptpubkey"]
        inputs += compact(len(scriptpubkey)//2).hex()
        inputs += output["scriptpubkey"]
    locktime = struct.pack("<I", tx_data["locktime"]).hex()
    serialized_tx = version + vin_length + inputs  + locktime + "01000000"
    message = hashlib.sha256(hashlib.sha256(bytes.fromhex(serialized_tx)).digest()).digest()

    return message


def checksig(pubkey, signature, message):
    try:
        public_key_bytes = bytes.fromhex(pubkey)
        signature_bytes = bytes.fromhex(signature[:-2])
        message_bytes = bytes.fromhex(message.hex())
        
        verik = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)

        # Verify the signature
        is_ok = verik.verify_digest(signature_bytes, message_bytes, sigdecode=ecdsa.util.sigdecode_der)
        return is_ok
    except BadSignatureError:
        return False


def validate_transaction(combined_script, tx_data, index):
    tokens = tokenize(combined_script)
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
            message = message_construction(tx_data, index)
            return checksig(pubkey, signature, message)
            
        
 
        i += 1



def p2pkh_verifier(folder, dest_folder):
    files = os.listdir(folder)
    os.makedirs(dest_folder, exist_ok=True)
    for file in files:
        f = open(os.path.join(folder, file))
        data = json.load(f)
        if valid_p2pkh(data):
            print(f"{file} is valid")
            shutil.copyfile(os.path.join(folder, file), os.path.join(dest_folder, file))
        else:
            print(f"{file} is invalid")

def valid_p2pkh(tx_data):
    ans = False
    for i, vin in enumerate(tx_data["vin"]):
        pubkeyasm = vin["prevout"]["scriptpubkey_asm"]
        scriptsigasm = vin["scriptsig_asm"]
        final = scriptsigasm + " " + pubkeyasm
        ans = validate_transaction(final, json.dumps(tx_data), i)
    return ans

