import hashlib


# Function to generate hash value of files
def getHashFromName(fileName):
    md5hash = hashlib.sha256()
    with open(fileName, "rb") as f:
        md5hash.update(f.read())
        return md5hash.hexdigest()


# Function to generate hash value of files
def getHashFromData(fileData):
    md5hash = hashlib.sha256()
    md5hash.update(fileData)
    return md5hash.hexdigest()
