import os
import csv
import sys
import pytsk3
import pyewf
import sqlite3
import pandas as pd
from os import listdir
from os.path import isfile, join
from datetime import datetime
from hashSum import getHashFromName, getHashFromData


# function to process the selected image file
def processImage(image, img_type, output, part_type, save=True, computeHash=True):
    volume = None
    print("[+] Opening {}".format(image))
    if img_type == "ewf":
        try:
            filenames = pyewf.glob(image)
        except IOError as e:
            print("[-] Invalid EWF format:n {}".format(e))
            sys.exit(2)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)
        # Open PYTSK3 handle on EWF Image
        img_info = ewf_Img_Info(ewf_handle)
    else:
        img_info = pytsk3.Img_Info(image)

    try:
        if part_type is not None:
            attr_id = getattr(pytsk3, "TSK_VS_TYPE_" + part_type)
            volume = pytsk3.Volume_Info(img_info, attr_id)
        else:
            volume = pytsk3.Volume_Info(img_info)
    except IOError as e:
        print("[-] Unable to read partition table:n {}".format(e))
    fs_object = openFS(volume, img_info, output, save=save, computeHash=computeHash)
    return fs_object


# function to process the browser history found in the image
def processWebHistory(fileName, fs_object):
    # Download history datafiles
    chrome = "Documents and Settings/Administrator/Local Settings/Application Data/Google/Chrome/User Data/Default/History"
    firefox = "Documents and Settings/Administrator/Application Data/Mozilla/Firefox/Profiles/4wd37sh1.default/places.sqlite"
    exportFile(fs_object, chrome, "browser")
    exportFile(fs_object, firefox, "browser")

    # Extract and process Chrome History
    con = sqlite3.connect("./browser/History")
    c = con.cursor()
    query = "select url, title from urls"
    c.execute(query)
    results = c.fetchall()
    df = pd.DataFrame(results, columns=["URL", "Title"])
    df['Browser'] = 'Chrome'

    # Extract and process Firefox History
    con = sqlite3.connect("./browser/places.sqlite")
    c = con.cursor()
    query = "select moz_places.url, moz_places.title from moz_places;"
    c.execute(query)
    results = c.fetchall()
    df2 = pd.DataFrame(results, columns=["URL", "Title"])
    df2['Browser'] = 'Firefox'

    df_merge = pd.concat([df, df2])
    df_merge.to_csv(f"{fileName}_history.csv")


# function to export a selected file found in the image
def exportFile(fs_object, filePath=None, folder="extracted"):
    if filePath is None:
        # Get path of file
        filePath = input("Enter object filePath: ")
    fileName = f"./{folder}/" + filePath.split("/")[-1]
    try:
        fileObject = fs_object.open(filePath)
        with open(fileName, 'wb') as f:
            filedata = fileObject.read_random(0, fileObject.info.meta.size)
            f.write(filedata)
        print(f"[+] File {fileName} Extracted Successfully.")
    except Exception as e:
        print(f"[-] Exception: {e}")


class ewf_Img_Info(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(ewf_Img_Info, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


# function to open the image file
def openFS(vol, img, output, save, computeHash):
    print("[+] Recursing through files..")
    recursed_data = []
    # Open FS and Recurse
    fs = None
    if vol is not None:
        for part in vol:
            if part.len > 2048 and b"Unallocated" not in part.desc and b"Extended" not in part.desc and b"Primary Table" not in part.desc:
                try:
                    fs = pytsk3.FS_Info(img, offset=part.start * vol.info.block_size)
                    root = fs.open_dir(path="/")
                    data = recurseFiles(str(part.addr), fs, root, [], [], [""], computeHash)
                    recursed_data.append(data)
                except IOError as e:
                    print("[-] Unable to open FS:n {}".format(e))
    else:
        try:
            fs = pytsk3.FS_Info(img)
            root = fs.open_dir(path="/")
            data = recurseFiles(1, fs, root, [], [], [""], computeHash)
            recursed_data.append(data)
        except IOError as e:
            print("[-] Unable to open FS:n {}".format(e))
    if save:
        csvWriter(recursed_data, output)
    return fs


# function to recursively step through the files and directories in the image
def recurseFiles(part, fs, root_dir, dirs, data, parent, computeHash):
    dirs.append(root_dir.info.fs_file.meta.addr)
    for fs_object in root_dir:
        # Skip ".", ".." or directory entries without a name.
        if not hasattr(fs_object, "info") or not hasattr(fs_object.info, "name") or not hasattr(fs_object.info.name,
                                                                                                "name"):
            continue

        file_name = fs_object.info.name.name.decode("utf-8")
        if file_name in [".", ".."]:
            continue

        try:
            file_name = fs_object.info.name.name.decode("utf-8")
            # file_path = "{}/{}".format(b"/".join(parent), fs_object.info.name.name)
            file_path = f'{"/".join(parent)}/{file_name}'

            try:
                if fs_object.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    f_type = "DIR"
                    file_ext = ""
                else:
                    f_type = "FILE"
                if "." in file_name:
                    file_ext = file_name.rsplit(".")[-1].lower()
                else:
                    file_ext = ""
            except AttributeError:
                continue

            size = fs_object.info.meta.size
            create = convertTime(fs_object.info.meta.crtime)
            change = convertTime(fs_object.info.meta.ctime)
            modify = convertTime(fs_object.info.meta.mtime)

            if computeHash:
                # Get Hash
                fileData = fs_object.read_random(0, fs_object.info.meta.size)
                hash = getHashFromData(fileData)
            else:
                hash = None

            data.append(
                ["PARTITION {}".format(part), file_name, file_ext, f_type, create, change, modify, size, file_path,
                 hash])

            if f_type == "DIR":
                parent.append(fs_object.info.name.name.decode("utf-8"))
                sub_directory = fs_object.as_directory()
                inode = fs_object.info.meta.addr
                # This ensures that we don't recurse into a directory
                # above the current level and thus avoid circular loops.
                if inode not in dirs:
                    recurseFiles(part, fs, sub_directory, dirs, data, parent, computeHash)
                    parent.pop(-1)
        except IOError:
            pass

    dirs.pop(-1)
    return data


# function to convert timestamp to UTC timezone
def convertTime(ts):
    if str(ts) == "0":
        return ""
    return datetime.utcfromtimestamp(ts)


# function to write output to csv file
def csvWriter(data, output):
    if data == []:
        print("[-] No output results to write")
        sys.exit(3)
    print("[+] Writing output to {}".format(output))
    with open(output, "w", newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        headers = ["Partition", "File", "File Ext", "File Type", "Create Date", "Modify Date", "Change Date", "Size",
                   "File Path", "SHA256 Hash"]
        csv_writer.writerow(headers)
        for result_list in data:
            csv_writer.writerows(result_list)


# List all available images
# Search for E01 image
def getLoadList():
    fileList = [f for f in listdir(os.getcwd()) if isfile(join(os.getcwd(), f))]
    fileList = [f for f in fileList if f.endswith(".E01")]
    return fileList
