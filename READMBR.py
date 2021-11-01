from tkinter import *  # widgets
from tkinter.filedialog import askopenfilename

# initialize window and give it some dimensions
window = Tk()
window.geometry('500x600')
window.title("Disk image reader")


# this method discovers fat volume information
def fat_info(filename, partition_start):
    result = "FAT Info:\nNumber of sectors per cluster is:  "
    with open(filename, "rb") as f:
        size = (partition_start * 512) + 1000 * 512
        disk_image = f.read(size)

        txt = disk_image[(partition_start * 512):]  # read from where fat volume info starts
        sectors_per_cluster = txt[13]  # single byte so no need to convert to little endian

        size_of_FAT = txt[22:24]  # reading info and converting to little endian + int
        number_of_copies = txt[16]
        size_of_FAT = int.from_bytes(size_of_FAT, byteorder='little')
        size_of_FAT = size_of_FAT * number_of_copies

        max_rt_dir_entries = txt[17:19]  # same here
        max_rt_dir_entries = int.from_bytes(max_rt_dir_entries, byteorder='little')
        rt_dir_size = max_rt_dir_entries * 32 / 512  # sector size is 512 in this example and dir entry size for FAT is always 32 bytes

        reserved_area = txt[14:16]
        reserved_area = int.from_bytes(reserved_area, byteorder='little')
        data_area = partition_start + reserved_area + size_of_FAT
        cluser2_start = data_area + rt_dir_size

        result += str(sectors_per_cluster)  # glue all info together
        result += "\nSize of FAT area in sectors: " + str(size_of_FAT)
        result += "\nRoot directory size in sectors: " + str(rt_dir_size)
        result += "\nCluster#2 start sectors is: " + str(cluser2_start)

        for i in range(0, int(rt_dir_size * 512), 32):
            file_title = txt[int((data_area * 512) - (partition_start * 512)) + i:]
            if file_title[0] == 229:
                result += "\nDeleted file name is: " + str(file_title[:11])
                result += "\nSize of that file is: " + str(int.from_bytes(file_title[28:32], byteorder='little'))
                result += "\nAddress of starting cluser for that file in decimal: " + str(
                    int.from_bytes(file_title[26:28], byteorder='little'))
                csa = cluser2_start + ((int.from_bytes(file_title[26:28], byteorder='little') - 2) * 8)
                file_content = txt[(int(csa) * 512) - (partition_start * 512):(int(csa) * 512) - (
                        partition_start * 512) + 16]
                result += "\nFirst 16 bytes of content of that file: " + str(
                    file_content) + "\n--------------------------------------------------------------"
                break

        display_info(result)  # display all that info


# this method discovers ntfs info, pattern is: take desired bytes and convert them to little endian + int
def ntfs_info(filename, partition_start):
    with open(filename, "rb") as f:
        size = (partition_start * 512) + 1000 * 512
        disk_image = f.read(size)

        txt = disk_image[(partition_start * 512):]

        bytes_per_sector = txt[11:13]
        bytes_per_sector = int.from_bytes(bytes_per_sector, byteorder='little')

        sectors_per_cluster = txt[13]

        mft_sector_address = txt[48:56]
        mft_sector_address = int.from_bytes(mft_sector_address, byteorder='little')

        txt = txt[((mft_sector_address * int(sectors_per_cluster)) * bytes_per_sector):]

        first_attribute_offset = txt[20:22]
        first_attribute_offset = int.from_bytes(first_attribute_offset, byteorder='little')

        first_attribute = txt[first_attribute_offset:(first_attribute_offset + 4)]
        first_attribute = int.from_bytes(first_attribute, byteorder='little')

        first_attribute_length = txt[(first_attribute_offset + 4):(first_attribute_offset + 8)]
        first_attribute_length = int.from_bytes(first_attribute_length, byteorder='little')

        second_attribut_offset = first_attribute_offset + first_attribute_length

        second_attribute = txt[second_attribut_offset:(second_attribut_offset + 4)]
        second_attribute = int.from_bytes(second_attribute, byteorder='little')

        second_attribut_length = txt[(second_attribut_offset + 4):(second_attribut_offset + 8)]
        second_attribut_length = int.from_bytes(second_attribut_length, byteorder='little')

        # here I return discovered info. I could have used a single variable as with FAT method, but I was too lazy.
        return "NTFS Info(all in decimal):\nBytes per sector is: " + str(
            bytes_per_sector) + "\nSectors per cluster is: " + str(
            sectors_per_cluster) + "\nMFT sector address: " + str(
            mft_sector_address) + "\nFirst attribute offset: " + str(
            first_attribute_offset) + "\nFirst attribute: " + str(first_attribute) + "\nFirst attribute length: " + str(
            first_attribute_length) + "\nSecond attribute offset: " + str(
            second_attribut_offset) + "\nSecond attribute: " + str(
            second_attribute) + "\nSecond attribute length: " + str(second_attribut_length)


# this function takes the final result in form of a string and puts it into label that gets  displayed in window
def display_info(txt):
    lbl = Label(window, text=txt)
    lbl.pack()


def check(x):  # checks for the partition type NB: decimal format
    return {
        0: 'Unknown or empty',
        1: '12-bit FAT',
        4: '16-bit FAT (<32MB)',
        5: 'Extended Ms-DOS Partition',
        6: 'FAT-16 (32MB to 2GB)',
        7: 'NTFS',
        11: 'FAT-32 (CHS)',
        12: 'FAT-32 (LBA)',
        14: 'FAT-16(LBA)',
    }[x]


# this method allows for file upload and it also glues all info received together
def upload_file():
    filename = askopenfilename()  # takes file and puts it into variable
    txt = ""
    type_txt = ""
    ntfs_exists = False
    for partition_no in range(1, 5):  # only 4 iterations because there is max of 4 partitions
        txt += "Partition " + str(partition_no) + ": "  # create initial string and as it goes, keep adding info
        txt += "Start Sector is "
        start_txt = partition_start(filename, partition_no)  # info where partiton starts
        txt += start_txt
        txt += partition_size(filename, partition_no)  # info what is the size
        type_txt = partition_type(filename, partition_no)  # infor what is the type
        txt += "Type is " + type_txt
        txt += "\n"  # new space is for another iteration - each iteration is next partition

        if type_txt == 'NTFS':
            ntfs_exists = True
            ntfs_txt = ntfs_info(filename, int(start_txt))

    display_info(
        txt)  # in ealier versions this method was called at the very end (after for loop ends), but I discovered txt looks nicer that way
    display_info(
        "--------------------------------------------")  # this makes a nice line under partition info so its easier to read other info
    if ntfs_exists:
        display_info(ntfs_txt)  # ntfs info gets displayed


# this method discovers where partiton starts
def partition_start(filename, partition_no):  # the file and partition no. we investigate gets passed
    with open(filename, "rb") as f:  # read as binary
        size = 446 + (16 * partition_no)  # each partiton is 16 bytes. First 466 bytes is the initial MBR info
        disk_image = f.read(size)  # take the bytes I want to read and put them into variable
        txt = disk_image[-8:-4]  # put into variable bytes where info on partition start is stored
        # txt = txt[::-1] # in ealier versions of this program I was using this line to convert to little endian
        txt = int.from_bytes(txt,
                             byteorder='little')  # in current version of this program, I use this to convert to little endian

        if partition_no == 1:
            fat_info(filename, txt)

        return str(txt)


# this method extracts info about partition size
def partition_size(filename, partition_no):  # accept disk image and partition no. we investigate
    with open(filename, "rb") as f:  # read as binary
        size = 446 + (16 * partition_no)  # 446 inital bytes + partition we are interested in
        disk_image = f.read(size)
        txt = disk_image[-4:]  # bytes where information is stored
        # txt = txt[::-1] # used before to convert to little endian
        txt = int.from_bytes(txt, byteorder='little')  # using this now to convert to little endian
        txt = ", Size is " + str(txt) + " sectors, "  # put in nice string format
        return txt


# this method checks for partition type
def partition_type(filename, partition_no):
    with open(filename, "rb") as f:
        size = 446 + (16 * partition_no)
        disk_image = f.read(size)
        txt = disk_image[-12:-11]  # bytes where information is stored
        txt = int.from_bytes(txt,
                             byteorder='little')  # its a single byte so there is probably no need for this, but left it in case I need it in future
        return check(txt)  # check() method takes byte and returns string which is the name of the type


# this creates the upload button which is used to upload disk image and run whole program
upld_btn = Button(window, text="Upload disk image", command=upload_file)
upld_btn.pack()

window.mainloop()
