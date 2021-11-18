import requests
from eth_account import Account
from eth_keys import keys
from eth_utils import decode_hex


def bruteforce(false_private_key):
    # this function build a dictionnary that contains all the possible pk and the associate address

    # this dict will contain all of that
    allPossibility = {}

    # this list contain all of the 0-9A-Za-z char (as int)
    allCharsCode = [i for i in range(ord('A'), ord('Z') + 1)] + [i for i in range(ord('0'), ord('9') + 1)] + [i for i in range(ord('a'),ord('z') + 1)]

    for j in range(len(false_private_key)):
        #for each char of the pk we re gonna to

        for i in allCharsCode:
            #circle through all the possibilites

            # some junk to modify the char i of a string
            pk = list(false_private_key)
            pk[j] = chr(i)
            pk = ''.join(pk)
            allPossibility[pk] = None

    # for each pk that derives from the original false pk we get the address (wich is not the pb, but derives from it)
    for pk in allPossibility.keys():
        try:
            allPossibility[pk] = getAddressFromPrivateKey2(pk)

        # sometimes a pk does not have a pb so we ignore it (long story short the pk is in char, not in bytes so sometimes there is no pb associate)
        except Exception:
            pass

    # print this dict (to check how many pk have a pb, if it does not render then you have more than 1 char wrong...)
    for pk in allPossibility.keys():
        if allPossibility[pk]:
            print(pk, allPossibility[pk])
    return allPossibility


def getAddressFromPrivateKey(private_key):
    # get the address of a pk
    private_key = "0x" + private_key
    acct = Account.from_key(private_key)
    return "0x" + str(acct.address)

def getAddressFromPrivateKey2(pk):
    # same as the function up, but had to double check in case something was wrong. Anyway they work the same
    priv_key_bytes = decode_hex("0x" + str(pk))
    priv_key = keys.PrivateKey(priv_key_bytes)
    pub_key = priv_key.public_key
    return pub_key.to_checksum_address()

def make_request(address):
    # make a request to bscan to check if there is any BNB, if not it ignore the pk and associate address

    url = f'https://api.bscscan.com/api'
    # defining a params dict for the parameters to be sent to the API
    params = {'module': 'account',
              'action': 'balance',
              'address': '0x' + str(address),
              'apikey': 'N7YA98RSZQ2IP3ZIJXPZ7MRYI94G32V11N'}
    # sending get request and saving the response as response object
    r = requests.get(url=url, params=params)
    res = r.json()
    if res['status'] == "1":
        amountBNB = res['result']
        if float(amountBNB) > 0:
            return True
    else:
        print('Need new API key...')

def main():
    # the main function that put all the orchester in place

    # VARIABLE TO MODIFY (this is not my pk...)
    private_key_to_bruteforce = 'c6cbd7d76bc5baca530c875663711b947efa6a86a900a9e8645ce32e5821484e'
    print('Building dictionnary of valid private keys ...')
    possibilities = bruteforce(private_key_to_bruteforce)
    print('Dictionnary successfully built ! ')

    # for each pk that works
    for pk in possibilities.keys():

        # if the pk has a pb
        if possibilities[pk]:

            # then i make the call
            if make_request(possibilities[pk]):

                # hopefully you get here eventually
                print(' >>>>>>>>>>>> Hello money <<<<<<<<<<<< : ', pk)
            
            else:
                # sorry, I think you will get that a lot...
                print(possibilities[pk], 'is empty :(')

# do the work
main()
