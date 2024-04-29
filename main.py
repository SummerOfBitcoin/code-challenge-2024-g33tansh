#Importing required Libraries and functions...
from mine import txidlist_calc, blockheader, coin_base, create_output
from filtering import filp2pkh, filp2wpkh
from P2PKH_TV import p2pkh_verifier
from P2WPKH_TV import p2wpkh_verifier

#Filtering p2pkh and p2wpkh transactions from mempool
filp2pkh("./mempool", "./p2pkh")
filp2wpkh("./mempool", "./p2wpkh")

#Validating p2pkh and p2wpkh transactions
p2pkh_verifier("./p2pkh", "./ver")
p2wpkh_verifier("./p2wpkh", "./ver")

#Mining process
txList = txidlist_calc("./ver")
coinbe = coin_base("./ver")
blockz = blockheader(txList)

#Creating output.txt for Autograder..
create_output(blockz, coinbe, txList)




