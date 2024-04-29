import os
import json
from shutil import copyfile

def filp2pkh(in_folder, out_folder):
    os.makedirs(out_folder, exist_ok=True)

    for file in os.listdir(in_folder):
        if file.endswith(".json"):
            in_file_path = os.path.join(in_folder, file)
            out_file_path = os.path.join(out_folder, file)

            with open(in_file_path, "r") as in_file:
                data = json.load(in_file)

                all_p2pkh = all(vin["prevout"]["scriptpubkey_type"] == "p2pkh" for vin in data["vin"])

                if all_p2pkh:
                    copyfile(in_file_path, out_file_path)


def filp2wpkh(in_folder, out_folder):
    os.makedirs(out_folder, exist_ok=True)

    for file in os.listdir(in_folder):
        if file.endswith(".json"):
            in_file_path = os.path.join(in_folder, file)
            out_file_path = os.path.join(out_folder, file)

            with open(in_file_path, "r") as in_file:
                data = json.load(in_file)

                any_p2wpkh = any(vin["prevout"]["scriptpubkey_type"] == "v0_p2wpkh" for vin in data["vin"])
                single_input = len(data.get("vin", [])) == 1

                if any_p2wpkh and single_input:
                    copyfile(in_file_path, out_file_path)

