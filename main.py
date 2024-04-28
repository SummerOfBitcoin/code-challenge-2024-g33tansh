from Mining import json_parse, blockheader, coinbase, create_output
from p2pkh import filter_tx
from P2PKH_TV import p2pkh_verifier



filter_tx("./mempool", "./uv_p2pkh")
print("Filter complete")
p2pkh_verifier("./uv_p2pkh/", "./p2pkh")
print("Verification done")


txidlist = json_parse("p2pkh/")
blockhead = blockheader(txidlist)
print(blockhead)
coinbas = coinbase(txidlist)


create_output(blockhead, coinbas, txidlist)
