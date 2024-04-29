#------------------------------------------#
# Filtering P2PKH and P2WPKH Transacations # 
# from mempool                             #
#------------------------------------------#


#Importing libraries..
import os
import json
from shutil import copyfile


#Function that filters out P2PKH json files from mempool
def filp2pkh(inf, outf):
    os.makedirs(outf, exist_ok=True)

    for file in os.listdir(inf):
        if file.endswith(".json"):
            in_path = os.path.join(inf, file)
            out_path = os.path.join(outf, file)

            with open(in_path, "r") as in_file:
                data = json.load(in_file)

                all_p2pkh = all(vin["prevout"]["scriptpubkey_type"] == "p2pkh" for vin in data["vin"])

                if all_p2pkh:
                    copyfile(in_path, out_path)

#Function to filter out P2WPKH transactions from mempool 
def filp2wpkh(inf, outf):
    os.makedirs(outf, exist_ok=True)

    for file in os.listdir(inf):
        if file.endswith(".json"):
            in_path = os.path.join(inf, file)
            out_path = os.path.join(outf, file)

            with open(in_path, "r") as in_file:
                data = json.load(in_file)

                p2wpkh = any(vin["prevout"]["scriptpubkey_type"] == "v0_p2wpkh" for vin in data["vin"])
                single_input = len(data.get("vin", [])) == 1

                if p2wpkh and single_input:
                    copyfile(in_path, out_path)

