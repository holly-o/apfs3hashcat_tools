import plistlib
import os, io
from PIL import Image
import re
import argparse
import json

def printUserInfo(key, userDict):
    print("Full name:", userDict[key]['FullName'])
    print("Short name:", userDict[key]['ShortName'])
    if userDict[key].get('PasswordHint'):
        print("Password hint:", userDict[key]['PasswordHint'])
    if userDict[key].get('hasImage'):
        print("Image at", userDict[key]['imageLocation'])


def printExtraInfo(key, userDict, encryptedRootDict):
    if encryptedRootDict.get(key):
        for info in encryptedRootDict[key]['decodedOtherUserData']:
            if info not in [userDict[key]['FullName'], userDict[key]['ShortName']]:
                print("Possible extra name data:", info)

        if encryptedRootDict[key]['FullName'] != userDict[key]['FullName']:
            print("Possible alternative full name:",encryptedRootDict['FullName'])

        if encryptedRootDict[key]['PassphraseHint'] != userDict[key]['PasswordHint']:
            print("Possible alternative password hint:", encryptedRootDict['PassphraseHint'])



def printHashcatHash(key, hashDict):
    hashcat_hash = hashDict[key]['hashcat_hash']

    assert(hashcat_hash[0:6] == "$fvde$")
    if hashcat_hash[6] == "1":
        mode = 16700
    elif hashcat_hash[6] == "2":
        mode = 18300
    assert(hashcat_hash[6] in ["1","2"])

    print(f"Hashcat hash:{hashcat_hash} (mode {mode})")

def main():

    ICLOUD_RECOVERY_KEY = "EC1C2AD9B6184ED6BD8D50F361C27507"

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', type=str, required=True, help="Directory to save image")
    parser.add_argument('-r', type=str, required=True, help="Path to root directory")
    parser.add_argument('-j', type=str, required=True, help="Path to JSON file")

    # python3 magic_key.py -i . -r /tmp/apfs/apfs -j example/out.json

    args = parser.parse_args()
    
    imageDirc = args.i
    rootPath = os.path.join(args.r, "root")

    with open(args.j) as jsonFile:
        hashDict = json.load(jsonFile)

    userDict = {}
    encryptedRootDict = {}

    uuidPattern = re.compile("[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")


    # loop even though only expecting to find one
    for UUID_with_dash in os.listdir(rootPath):
        dirc = os.path.join(rootPath, UUID_with_dash)
        if not os.path.isdir(dirc):
            continue
        if not uuidPattern.match(UUID_with_dash):
            continue

    
        CryptoPath = os.path.join(rootPath,UUID_with_dash,"var","db","CryptoUserInfo.plist")
        with open(CryptoPath, "rb") as CryptoUserInfo:
            d = plistlib.load(CryptoUserInfo)
            for k in d.keys():

                key = k.replace("-","")

                userDict[key] = {}

                for dictEntry in ['FullName', 'ShortName', 'PasswordHint', 'UserType', 'PictureData']:
                    userDict[key][dictEntry] = d[k].get(dictEntry)
            
                PictureData = d[k].get('PictureData')
                if PictureData:
                    # open using PIL to find extension
                    image = Image.open(io.BytesIO(PictureData))
                    extension = image.format.lower()
                
                    with open(os.path.join(imageDirc, "image_{}.{}".format(key, extension)), "wb") as image_file:
                        image_file.write(PictureData)

                    userDict[key]['hasImage'] = True
                    userDict[key]['imageLocation'] = os.path.join(imageDirc, "image_{}.{}".format(key, extension))





        encryptedRootPath = os.path.join(rootPath, UUID_with_dash,"System","Library","Caches", "com.apple.corestorage", "EncryptedRoot.plist.wipekey")
        with open(encryptedRootPath, "rb") as encryptedRootInfo:
            d = plistlib.load(encryptedRootInfo)
            #keys should be CryptoUsers which contains info we need and WrappedVolumeKeys which is empty
            #check which of 0 and 1 gives you the correct key
            userIndex = 0
            for i in range(len(d['CryptoUsers'])):
                #This is the good number i.e. not iCloud
                if d['CryptoUsers'][i].get('UserType') == "268828674":
                    userIndex = i
            FullName = d['CryptoUsers'][userIndex].get('UserFullName')
            UUID_key = d['CryptoUsers'][userIndex].get('UserIdent')
            PassphraseHint = d['CryptoUsers'][userIndex].get('PassphraseHint')
            OtherUserData = d['CryptoUsers'][userIndex].get('UserNamesData', [])
            decodedOtherUserData = [b.decode() for b in OtherUserData]

            encryptedRootDict[UUID_key.replace("-","")] = {'FullName':FullName, 'PassphraseHint':PassphraseHint, 'decodedOtherUserData':decodedOtherUserData}
 

            # can also sometimes look at /var/db/LegacyEncryptedRoot.plist.wipekey but the EncryptedRoot.plist.wipekey is better


    hashKeys = set(hashDict.keys())
    hashKeys.discard(ICLOUD_RECOVERY_KEY)
    userKeys = set(userDict.keys()) 
    userKeys.discard(ICLOUD_RECOVERY_KEY)

    if len(hashKeys) == 0:
        print("No valid keys found in JSON file. Unable to generate Hashcat hash.")
        # return 0
        

    if len(userKeys) == 0:
        print("Warning! No valid keys found in plist file. Unable to generate user info")

    dictSet = hashKeys.intersection(userKeys)
    # Put keys into list, loop round list even though most of the time we'll only have one key
    
    # use if no matches
    hashKeyList = []
    userKeyList = []

    # use if matches found
    matchedKeyList = []

    # always get rid of recovery key because we won't use this key

    # ideal case
    # two identical keys in each of hashDict and userDict, one recovery, one hashKey
    # i.e intersection size 1
    if len(dictSet) > 0:
        matchedKeyList.extend(list(dictSet))

        #we want len(dictSet) == 1 ideally but else can loop over all matches

        if len(dictSet) != 1:
            print("Warning! Found multiple hash keys that match")

    else:    
        print("Warning! No key match between plist and JSON files")    
        hashKeyList.extend(list(hashKeys))
        userKeyList.extend(list(userKeys))

        if len(hashKeys) > 1:
            print("Warning! Multiple hash keys found")


    if matchedKeyList:
        for key in matchedKeyList:
            printHashcatHash(key, hashDict)
            printUserInfo(key, userDict)
            printExtraInfo(key, userDict, encryptedRootDict)


    else:
        for hashKey in hashKeyList:
            printHashcatHash(hashKey, hashDict)
        for userKey in userKeyList:
            printUserInfo(userKey, userDict)
            printExtraInfo(userKey, userDict, encryptedRootDict)

    return 0

if __name__ == "__main__":
    main()
