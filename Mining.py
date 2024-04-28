import os
import json
import struct
import hashlib
import time 

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def merkle_root(txids):
    txids = list(txids)
    if len(txids) == 1:
        return txids[0]
    newtxids = []
    # Process pairs. For odd length, the last is skipped
    for i in range(0, len(txids)-1, 2):
        newtxids.append(hash2(txids[i], txids[i+1]))
    if len(txids) % 2 == 1: # odd, hash last item twice
        newtxids.append(hash2(txids[-1], txids[-1]))
    return merkle_root(newtxids)

def hash2(a, b):
    # Reverse inputs before and after hashing
    a1 = bytes.fromhex(a)[::-1]
    b1 = bytes.fromhex(b)[::-1]
    h = hashlib.sha256(hashlib.sha256(a1+b1).digest()).digest()
    return h[::-1].hex()


def compact_size(value):
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')

def hash_txid(json_data):
    tx_data = json.loads(json_data) 
    inputs = ""
    inputs += struct.pack("<I", tx_data["version"]).hex()
    inputs += compact_size(len(tx_data["vin"])).hex()
    
    for v_input in tx_data["vin"]: 
            inputs += ''.join(reversed([v_input['txid'][i:i+2] for i in range(0, len((v_input['txid'])), 2)]))
            inputs += struct.pack("<I", v_input["vout"]).hex()
            inputs += compact_size(len(v_input["scriptsig"])//2).hex() 
            inputs += v_input["scriptsig"]
            inputs += struct.pack("<I", v_input["sequence"]).hex()
    inputs += compact_size(len(tx_data["vout"])).hex()
    for output in tx_data["vout"]:
        inputs += struct.pack("<Q", int(output["value"])).hex()
        scriptpubkey = output["scriptpubkey"]
        inputs += compact_size(len(scriptpubkey)//2).hex()
        inputs += output["scriptpubkey"]
    locktime = struct.pack("<I", tx_data["locktime"]).hex()
    serialized_tx = inputs  + locktime
    cod = hashlib.sha256(hashlib.sha256(bytes.fromhex(serialized_tx)).digest()).digest()

    return cod[::-1].hex()


def json_parse(folder):
    # Get all JSON files from the folder
    json_files = [f for f in os.listdir(folder) if f.endswith('.json')]

    # Read JSON data from each file and calculate hashed txids
    hashed_txids = []
    for json_file in json_files:
        with open(os.path.join(folder, json_file), 'r') as file:
            json_data = file.read()
            hashed_txid = hash_txid(json_data)
            hashed_txids.append(hashed_txid)
    
    # Return the list of hashed txids
    return hashed_txids

def blockheader(txidlst):
    ver = "00000020"
    prevblock = "0000000000000000000000000000000000000000000000000000000000000000"
    txidlst = ["0000000000000000000000000000000000000000000000000000000000000000"] + txidlst
    merkleroot = merkle_root(txidlst)
    target_bits = 0x1f00ffff
    exp = target_bits >> 24
    mant = target_bits & 0xffffff
    target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
    target_str = bytes.fromhex(target_hexstr)
    nonce = 0

    while nonce < 0x100000000:
        bytes.fromhex(ver) + bytes.fromhex(prevblock)[::-1] +\
            bytes.fromhex(merkleroot)[::-1] + struct.pack("<LLL", int(hex(int(time.time())),16), target_bits, nonce)
        hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        # print(nonce, (hash[::-1]).hex())
        if hash[::-1] < target_str:
            return header.hex()
        nonce += 1


def coinbase(txids):
    witness_hash = bytes.fromhex(merkle_root(txids))
    witness_hash = witness_hash[::-1].hex()
    coinbase = ""
    coinbase += "01000000" #Version
    coinbase += "00" #Marker
    coinbase += "01" #Flag
    coinbase += "01" #Input Count
    coinbase += (b'\x00'*32).hex() #TXID
    coinbase += "ffffffff" #VOUT
    coinbase += "25"
    coinbase += "03000000184d696e656420627920416e74506f6f6c373946205b8160a4"
    coinbase += "ffffffff"
    coinbase += "02"
    witkit = witness_hash + "0000000000000000000000000000000000000000000000000000000000000000" 
    commit = double_sha256(bytes.fromhex(witkit)).hex()
    coinbase += "f595814a00000000" + "19" + "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"
    coinbase += "0000000000000000" + "26" + f"6a24aa21a9ed{commit}" 
    coinbase += "01" + "20" + "0000000000000000000000000000000000000000000000000000000000000000"
    coinbase += "00000000"

    return coinbase

    
def create_output(blockheader, coinbase, txidlist):
    with open('output.txt', 'a') as file:
        file.write(blockheader)
        file.write("\n"+coinbase)
        empty = (b'\x00'*32).hex()
        file.write(f"\n{empty}")
        for txid in txidlist:
            file.write("\n"+txid)
        

