import os
import json
import struct
import hashlib
import time 

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()
def hash256(data):
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

    txid = ""
    tx_data = json.loads(json_data)
    txid += struct.pack('<I', tx_data['version']).hex()
    txid += compact_size(len(tx_data['vin'])).hex()

    for vin in tx_data['vin']:
        txid += ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
        txid += struct.pack('<I', vin['vout']).hex()
        txid += compact_size(len(vin['scriptsig'])//2).hex()
        txid += vin['scriptsig']
        txid += struct.pack('<I', vin['sequence']).hex()
        
    txid += compact_size(len(tx_data['vout'])).hex()
    
    for vout in tx_data['vout']:
        txid += struct.pack('<Q', vout['value']).hex()
        txid += compact_size(len(vout['scriptpubkey'])//2).hex()
        txid += vout['scriptpubkey']
    txid += struct.pack('<I', int(tx_data['locktime'])).hex()
    txid_hash = hash256(bytes.fromhex(txid))
    return txid_hash[::-1].hex()



def txidlist_calc(folder):
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
    # header = bytes.fromhex(ver)
    while nonce < 0x100000000:
        header = bytes.fromhex(ver) + bytes.fromhex(prevblock)[::-1] +\
            bytes.fromhex(merkleroot)[::-1] + struct.pack("<LLL", int(hex(int(time.time())),16), target_bits, nonce)
        hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        # print(nonce, (hash[::-1]).hex())
        if hash[::-1] < target_str:
            return header.hex()
        nonce += 1

def txid_p2wpkh(json_data):
    tx_data = json.loads(json_data)

    txid = ""
    txid += struct.pack('<I', tx_data['version']).hex()
    txid += "00"
    txid += "01"
    txid += "01"
    for vin in tx_data['vin']:
        txid += ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
        txid += struct.pack('<I', vin['vout']).hex()
        txid += compact_size(len(vin['scriptsig'])//2).hex()
        txid += struct.pack('<I', vin['sequence']).hex()     
    txid += compact_size(len(tx_data['vout'])).hex()
    
    for vout in tx_data['vout']:
        txid += struct.pack('<Q', vout['value']).hex()
        txid += compact_size(len(vout['scriptpubkey'])//2).hex()
        txid += vout['scriptpubkey']
    witness = tx_data["vin"][0]["witness"]
    signature = witness[0]
    pubkey = witness[1]
    txid += signature + pubkey
    txid += struct.pack('<I', int(tx_data['locktime'])).hex()
    txid_hash = hash256(bytes.fromhex(txid))
    return txid_hash[::-1].hex()



def wtxid_p2wpkh(json_data): 
    tx_data = json.loads(json_data)
    wtx = ""
    wtx += struct.pack('<I', tx_data['version']).hex()
    wtx += "00"
    wtx += "01"
    wtx += "01"
    for vin in tx_data['vin']:
        wtx += ''.join(reversed([vin['txid'][i:i+2] for i in range(0, len(vin['txid']), 2)]))
        wtx += struct.pack('<I', vin['vout']).hex()
        wtx += compact_size(len(vin['scriptsig'])//2).hex()
        wtx += struct.pack('<I', vin['sequence']).hex()     
    wtx += compact_size(len(tx_data['vout'])).hex()
    for vout in tx_data['vout']:
        wtx += struct.pack('<Q', vout['value']).hex()
        wtx += compact_size(len(vout['scriptpubkey'])//2).hex()
        wtx += vout['scriptpubkey'] 
    witness = tx_data["vin"][0]["witness"]
    signature = witness[0]
    pubkey = witness[1]
    wtx += "02"
    wtx += compact_size(len(signature)//2).hex()
    wtx += signature
    wtx += compact_size(len(pubkey)//2).hex()
    wtx += pubkey
    wtx += struct.pack('<I', int(tx_data['locktime'])).hex()
    wtx_hash = hash256(bytes.fromhex(wtx))
    return wtx_hash[::-1].hex()




def coin_base(folder):
    witness_lists = wtxid_list(folder)
    witness_hash = merkle_root(witness_lists)
    witness_hash = witness_hash[::-1].hex()
    coinbase = ""
    coinbase += "01000000" # Version
    coinbase += "00" # Marker
    coinbase += "01" # Flag
    coinbase += "01" # Input Count
    coinbase += (b'\x00'*32).hex() # TXID
    coinbase += "ffffffff" # VOUT
    coinbase += "1d"
    coinbase += "03000000184d696e656420627920416e74506f6f6c373946205b8160a4"
    coinbase += "ffffffff"
    coinbase += "02"
    witkit = witness_hash + "0000000000000000000000000000000000000000000000000000000000000000" 
    witness_commitment = hash256(bytes.fromhex(witkit)).hex()

    coinbase += "f595814a00000000" + "19" + "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"
    coinbase += "0000000000000000" + "26" + f"6a24aa21a9ed{witness_commitment}" 
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
        


def wtxid_list(folder):
    wtxid = ["0000000000000000000000000000000000000000000000000000000000000000"] 
    files = os.listdir(folder)
    for file in files:
        filedata = open(folder + "/" + file)
        data = json.load(filedata)
        data_v = data["vin"][0]["prevout"]["scriptpubkey_type"]
        if data_v == "v0_p2wpkh":
            wtxid.append(wtxid_p2wpkh(json.dumps(data)))
        else: 
            wtxid.append(hash_txid(json.dumps(data)))
    return wtxid