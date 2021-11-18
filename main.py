import requests
from eth_account import Account
from eth_keys import keys
from eth_utils import decode_hex


def bruteforce(false_private_key):
    allPossibility = {}
    allCharsCode = [i for i in range(ord('A'), ord('Z') + 1)] + [i for i in range(ord('0'), ord('9') + 1)] + [i for i in range(ord('a'),ord('z') + 1)]

    for j in range(len(false_private_key)):
        for i in allCharsCode:
            pk = list(false_private_key)
            pk[j] = chr(i)
            pk = ''.join(pk)
            allPossibility[pk] = None

    for pk in allPossibility.keys():
        try:
            allPossibility[pk] = getAddressFromPrivateKey2(pk)
        except Exception:
            pass

    for pk in allPossibility.keys():
        if allPossibility[pk]:
            print(pk, allPossibility[pk])
    return allPossibility


def getAddressFromPrivateKey(private_key):
    private_key = "0x" + private_key
    acct = Account.from_key(private_key)
    return "0x" + str(acct.address)

def getAddressFromPrivateKey2(pk):
    priv_key_bytes = decode_hex("0x" + str(pk))
    priv_key = keys.PrivateKey(priv_key_bytes)
    pub_key = priv_key.public_key
    return pub_key.to_checksum_address()

def make_request(address):
    url = f'https://api.bscscan.com/api'
    # defining a params dict for the parameters to be sent to the API
    params = {'module': 'account',
              'action': 'balance',
              'address':  str(address),
              'apikey': 'N7YA98RSZQ2IP3ZIJXPZ7MRYI94G32V11N'}
    # sending get request and saving the response as response object
    r = requests.get(url=url, params=params)
    r = requests.get(url=f'https://api.bscscan.com/api?module=account&action=balance&address={str(address)}&apikey=N7YA98RSZQ2IP3ZIJXPZ7MRYI94G32V11N')
    res = r.json()
    if res['status'] == "1":
        amountBNB = res['result']
        if float(amountBNB) > 0:
            return True
    else:
        print('Need new API key...')

def main():
    private_key_to_bruteforce = ''
    print('Building dictionnary of valid private keys ...')
    possibilities = bruteforce(private_key_to_bruteforce)
    print('Dictionnary successfully built ! ')
    for pk in possibilities.keys():
        if possibilities[pk]:
            if make_request(str(possibilities[pk])):
                print(' >>>>>>>>>>>> Hello money <<<<<<<<<<<< : ', pk)
            else:
                print(possibilities[pk], 'is empty :(')

main()