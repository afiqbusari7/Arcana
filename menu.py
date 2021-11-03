import os
import validators
import pandas as pd

import logAnal
from virusTotalAPI import testHash, testURL
from processFunctions import processImage, getLoadList, processWebHistory, exportFile
from pathlib import Path
from hashSum import getHashFromName
from tabulate import tabulate
import subprocess
import webbrowser

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
pd.options.display.width = 0


# ===================== #
# Arcana Menu Functions #
# ===================== #

# Function to display arcana menu items
def arcanaMenu():
    print("""
===== Arcana Functions =====
1. Scan Raw Image
2. Scan File
3. Scan URL
4. Analyse Logs (LIVE)
5. User Manual
6. GitHub
7. Exit
""")

    userInput = input("Choose an option: ")
    return userInput


# Function for displaying available images in the directory
def chooseImage():
    loadList = getLoadList()
    if not loadList:
        print("No available images in folder. Please move raw image into the folder.")
        return None

    print("Available images in folder: ")
    for i, fileName in enumerate(loadList):
        print(i, fileName)
        while True:
            selection = input("\nChoose an image to process: ")
            if selection in [str(x) for x in list(range(len(loadList)))]:
                return fileName
            elif selection == "exit":
                print("Exiting the program..")
                exit()
            else:
                print("Invalid selection, please choose again.")


# Function for choosing the target image
def inputRawImage():
    fileName = chooseImage()
    if fileName is None:
        exit()

    print(f"{fileName} selected. Processing image..")

    outputFile = f"{fileName}_output.csv"
    historyFile = f"{fileName}_history.csv"

    # Check if outputFile exists
    if os.path.isfile(outputFile):
        choice = input("Image has been processed before, overwrite? (Y to overwrite) ")
    else:
        choice = 'y'

    # Save/Compute
    save_compute = choice.lower() in ['y', 'yes']

    # Process Image
    fs_object = processImage(
        image=fileName,
        img_type="ewf",
        output=outputFile,
        part_type=None,
        save=save_compute,
        computeHash=save_compute
    )

    while True:
        selection = rawImageMenu()

        if selection == "1":
            print(displayFiles(outputFile))
        elif selection == "2":
            print(searchFile(outputFile))
        elif selection == "3":
            exportFile(fs_object)
        elif selection == "4":
            print(displayWebHistory(fileName, fs_object))
        elif selection == "5":
            if not os.path.isfile(historyFile):
                displayWebHistory(fileName, fs_object)
            virusScanMenu(fileName)
        elif selection == "6":
            break
        elif selection == "7":
            print("Exiting the program..")
            exit()
        else:
            print("Invalid selection, please choose again.\n")


# Function to perform VirusTotal scan on a file in local directory
def inputFile():
    while True:
        selection = fileMenu()

        if selection == "1":
            fileString = input("\nInput directory of file you would like to scan: ")
            fileName = Path(fileString)
            # Check if file exists in directory
            if fileName.is_file():
                # Process File
                result = testHash(getHashFromName(fileName))
                # Add those which are malicious
                if result['malicious'] > 0:
                    verdict = 'Malicious'
                else:
                    verdict = 'Safe'

                # Format table
                print(tabulate([[fileString, verdict]], headers=['File', 'Verdict'], tablefmt='orgtbl'))
            else:
                print("File could not be found in directory, please choose again.")
        elif selection == "2":
            break
        elif selection == "3":
            print("Exiting the program..")
            exit()
        else:
             print("Invalid selection, please choose again.\n")

# Function to perform VirusTotal scan on a URL
def inputURL():
    while True:
        selection = URLMenu()

        if selection == "1":
            urlstring = input("\nInput URL you would like to scan eg. https://www.facebook.com: ")
            # Check if URL is valid
            if validators.url(urlstring) == True:
                # Process URL
                result = testURL(urlstring)
                # Add those which are malicious
                if result['malicious'] > 0:
                    verdict = 'Malicious'
                else:
                    verdict = 'Safe'

                # Format table
                print(tabulate([[urlstring, verdict]], headers=['URL', 'Verdict'], tablefmt='orgtbl'))
            else:
                print("URL is in the wrong format, please enter URL again. eg. https://www.facebook.com")
        elif selection == "2":
            break
        elif selection == "3":
            print("Exiting the program..")
            exit()
        else:
             print("Invalid selection, please choose again.\n")

# ======================== #
# Raw Image Menu Functions #
# ======================== #

# Function to display image menu items
def rawImageMenu():
    print("""
===== Raw Image Functions =====
1. Display Files
2. Keyword Search
3. Select File to Extract from Image
4. Process and Display Web History
5. Scan for Virus
6. Back
7. Exit
""")

    selection = input("Choose an option: ")
    return selection

# =================== #
# File Menu Functions #
# =================== #

def fileMenu():
    print("""
===== File Functions =====
1. Upload file from folder
2. Back
3. Exit
""")

    selection = input("Choose an option: ")
    return selection

# ================== #
# URL Menu Functions #
# ================== #

def URLMenu():
    print("""
===== URL Functions =====
1. Upload URL
2. Back
3. Exit
""")

    selection = input("Choose an option: ")
    return selection

# Function to store csv data into pandas dataframe
def getFiles(fileName):
    df = pd.read_csv(fileName)
    return df


# Function to iterate through pandas dataframe
def iterateResults(df):
    index = 50
    maxLen = len(df)
    dfs = []
    while True:
        if index >= maxLen:
            dfs.append(df[index - 50:])
            break
        else:
            dfs.append(df[index - 50:index])
        index += 50

    for df in dfs:
        print(df)
        nextData = input("'N' to cancel, else continue displaying next rows: ")
        if nextData in ["n", "N"]:
            break


# Function to display iterated files
def displayFiles(fileName):
    iterateResults(getFiles(fileName))


# Function to search for files containing specific keywords
def searchFile(fileName):
    searchString = input("Enter search: ")

    print(f"Searching for {searchString}..")
    df = getFiles(fileName)
    filtered_df = df.loc[df['File'].str.contains(searchString, case=False)]

    iterateResults(filtered_df)


# Function to identify the file path of the browser history
def getFullPath(fileName, regex):
    df = pd.read_csv(f"{fileName}_output.csv")
    return df[df["File Path"].str.contains(regex)].iloc[0]["File Path"]


# Function to display browser history found in the image
def displayWebHistory(fileName, fs_object):
    chrome_regex = "Google\/Chrome\/User Data\/\w+\/History"
    firefox_regex = "Mozilla\/Firefox\/Profiles\/.+\/places\.sqlite"

    chrome = getFullPath(fileName, chrome_regex)
    firefox = getFullPath(fileName, firefox_regex)

    processWebHistory(fileName, fs_object, chrome, firefox)

    try:
        df = pd.read_csv(f"{fileName}_history.csv", index_col=0)
        return df
    except Exception as e:
        print(f"Exception: {e}")
    return "No Web History found."


# ========================= #
# VirusTotal Menu Functions #
# ========================= #

# Function to display menu items for VirusTotal API
def virusScanMenu(fileName):
    # Select either full scan or single scan for file or url
    print("""
===== Virus Scan (VirusTotal) =====
1. Full Scan (All files and URLs)
2. Scan files by Keyword
3. Scan URLs by Keyword
4. Back
5. Exit
""")

    while True:
        selection = input("Choose an option: ")
        if selection == "1":
            fullScan(fileName)
            break
        elif selection == "2":
            selectedScan(fileName, "files")
            break
        elif selection == "3":
            selectedScan(fileName, "URLs")
            break
        elif selection == "4":
            break
        elif selection == "5":
            print("Exiting the program..")
            exit()
        else:
            print("Invalid selection, please choose again.\n")


# Function to store exported csv data to pandas dataframe
def getData(fileName, dataType="files"):
    if dataType == "files":
        print("Scanning Files..")
        file_df = pd.read_csv(f"{fileName}_output.csv")
        return file_df
    else:
        print("Scanning Websites..")
        url_df = pd.read_csv(f"{fileName}_history.csv", index_col=0)
        return url_df


# Function to perform VirusTotal scan on a file in the image
def fileScan(file_df):
    # Scan files
    files = []
    for index, row in file_df.iterrows():
        if index > 0:  # Limit testing to one file, due to API constraints
            break
        # Process Hash
        result = testHash(row['SHA256 Hash'])
        # Add those which are malicious
        if result['malicious'] > 0:
            verdict = 'Malicious'
        else:
            verdict = 'Safe'
        files.append([index, row['File Path'], verdict])

    return pd.DataFrame(files, columns=['Index', 'File Path', 'Verdict'])


# Function to perform VirusTotal scan on a URL in the image
def urlScan(url_df):
    # Scan URLs
    urls = []
    for index, row in url_df.iterrows():
        if index > 0:  # Limit testing to one URL, due to API constraints
            break
        # Process URL
        result = testURL(row['URL'])
        # Add those which are malicious
        if result['malicious'] > 0:
            verdict = 'Malicious'
        else:
            verdict = 'Safe'
        urls.append([index, row['URL'], verdict])

    return pd.DataFrame(urls, columns=['Index', 'URL', 'Verdict'])


# Function to perform VirusTotal scan on all files and URLs in the image
def fullScan(fileName):
    file_df = getData(fileName, "files")
    results_files = fileScan(file_df)

    url_df = getData(fileName, "URLs")
    results_URLs = urlScan(url_df)

    # Display files and websites which are malicious
    # path for files and url for websites
    print("Files: ")
    print(results_files)
    print("URLs: ")
    print(results_URLs)


# Function to prompt users for keywords when performing VirusTotal scan
def selectedScan(fileName, dataType="files"):
    if dataType == "files":
        searchString = input("Please enter the file path, or part thereof: ")
        print(f"Scanning Files ({searchString}): ")
        file_df = getData(fileName, "files")
        filtered_df = file_df.loc[file_df['File Path'].str.contains(searchString)]
        results_files = fileScan(filtered_df)

        print("\nFiles: ")
        print(results_files)
    else:
        searchString = input("Please enter the URL, or path thereof: ")
        print(f"Scanning Websites ({searchString}): ")
        url_df = getData(fileName, "URLs")
        filtered_df = url_df.loc[url_df['URL'].str.contains(searchString)]
        results_URLs = urlScan(filtered_df)

        print("\nURLs: ")
        print(results_URLs)


def main():
    print(r"""
           ________  ________  ________  ________  ________   ________     
          |\   __  \|\   __  \|\   ____\|\   __  \|\   ___  \|\   __  \    
          \ \  \|\  \ \  \|\  \ \  \___|\ \  \|\  \ \  \\ \  \ \  \|\  \   
           \ \   __  \ \   _  _\ \  \    \ \   __  \ \  \\ \  \ \   __  \  
            \ \  \ \  \ \  \\  \\ \  \____\ \  \ \  \ \  \\ \  \ \  \ \  \ 
             \ \__\ \__\ \__\\ _\\ \_______\ \__\ \__\ \__\\ \__\ \__\ \__\
              \|__|\|__|\|__|\|__|\|_______|\|__|\|__|\|__| \|__|\|__|\|__|
                  """)
    while True:
        userInput = arcanaMenu()

        if userInput == "1":
            inputRawImage()
        elif userInput == "2":
            inputFile()
        elif userInput == "3":
            inputURL()
        elif userInput == "4":
            path = input("Please enter the path to the directory containing the logs "
                               "(e.g. C:\Windows\System32\winevt\Logs) or enter \"1\" to use"
                               " default path: ")
            if int(path) == 1:
                logAnal.analyse("C:\Windows\System32\winevt\Logs")
            else:
                logAnal.analyse(path)
        elif userInput == "5":
            subprocess.Popen("User Manual.pdf", shell=True)
        elif userInput == "6":
            webbrowser.open('https://github.com/afiqbusari7/Arcana')
        elif userInput == "7":
            print("Exiting the program..")
            exit()
        else:
            print("Invalid selection, please choose again.\n")


if __name__ == "__main__":
    main()
