#--------------------------------------#
# P2PKH and P2WPKH Scripts Filtering   #
#--------------------------------------#

#Importing Libraries and functions..
import os
import json
from shutil import copyfile


#P2PKH script filtering function..
def filp2pkh(sourcef, destf):
    os.makedirs(destf, exist_ok=True)
    for file in os.listdir(sourcef):
        if file.endswith(".json"):
            in_path = os.path.join(sourcef, file)
            out_path = os.path.join(destf, file)
            with open(in_path, "r") as in_file:
                data = json.load(in_file)
                all_p2pkh = all(vin["prevout"]["scriptpubkey_type"] == "p2pkh" for vin in data["vin"])
                if all_p2pkh:
                    copyfile(in_path, out_path)

#P2PKH script filtering function..
def filp2wpkh(sourcef, destf):
    os.makedirs(destf, exist_ok=True)
    for file in os.listdir(sourcef):
        if file.endswith(".json"):
            in_path = os.path.join(sourcef, file)
            out_path = os.path.join(destf, file)
            with open(in_path, "r") as in_file:
                data = json.load(in_file)
                any_p2wpkh = any(vin["prevout"]["scriptpubkey_type"] == "v0_p2wpkh" for vin in data["vin"])
                single_input = len(data.get("vin", [])) == 1
                if any_p2wpkh and single_input:
                    copyfile(in_path, out_path)

