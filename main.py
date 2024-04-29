from mine import txidlist_calc, blockheader, koinbase, make_output
from libfilter import filp2pkh, filp2wpkh
from P2PKH_TV import p2pkh_verifier
from P2WPKH_TV import p2wpkh_verifier


#Filtering p2pkh and p2wpkh transactions from mempool
filp2pkh("./mempool", "./p2pkh")
filp2wpkh("./mempool", "./p2wpkh")

#Validating p2pkh and p2wpkh transactions
p2pkh_verifier("./p2pkh", "./ver")
p2wpkh_verifier("./p2wpkh", "./ver")

#Mining process
txid_list = txidlist_calc("./ver")
coinbe = koinbase("./ver")
blockz = blockheader(txid_list)

#Creating output.txt
make_output(blockz, coinbe, txid_list)




