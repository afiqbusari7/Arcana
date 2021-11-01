import hashlib


def getHashFromName(fileName):
    md5hash = hashlib.sha256()
    with open(fileName, "rb") as f:
        md5hash.update(f.read())
        return md5hash.hexdigest()


# function to get hash value of files
def getHashFromData(fileData):
    md5hash = hashlib.sha256()
    md5hash.update(fileData)
    return md5hash.hexdigest()

# print(getHashFromName("extract.py"))
