import os
import validators
import pandas as pd
from virusTotalAPI import testHash, testURL
from processFunctions import processImage, getLoadList, processWebHistory, exportFile
from pathlib import Path
from hashSum import getHashFromName
from tabulate import tabulate
import subprocess
import webbrowser

pd.set_option('display.max_columns', None)


def chooseImage():
    loadList = getLoadList()
    print("Available images in folder: ")
    for i, fileName in enumerate(loadList):
        print(i, fileName)
        while True:
            selection = input("\nChoose an image to process: ")
            if selection in [str(x) for x in list(range(len(loadList)))]:
                return fileName
            else:
                print("Invalid selection, please choose again.")


def getFullPath(fileName, regex):
    df = displayFiles(f"{fileName}_output.csv")
    return df[df["File Path"].str.contains(regex)].iloc[0]["File Path"]


def showInput():
    print("""
===== Arcana Input Types =====
1. Raw Image
2. File
3. URL
4. Exit
""")

    userInput = input("Choose an option: ")
    return userInput


def showMenu():
    print("""
===== Arcana Functions =====
1. Display Files
2. Keyword Search
3. Export File
4. Process and display Web History
5. Scan for Virus
6. User Manual
7. GitHub
8. Exit
""")

    selection = input("Choose an option: ")
    return selection


def displayFiles(fileName):
    df = pd.read_csv(fileName)
    return df


def searchFile(fileName):
    searchString = input("Enter search: ")

    print(f"Searching for {searchString}..")
    df = displayFiles(fileName)
    return df.loc[df['File'].str.contains(searchString, case=False)]


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


def getData(fileName, dataType="files"):
    if dataType == "files":
        print("Scanning Files..")
        file_df = pd.read_csv(f"{fileName}_output.csv")
        return file_df
    else:
        print("Scanning Websites..")
        url_df = pd.read_csv(f"{fileName}_history.csv", index_col=0)
        return url_df


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


def selectedScan(fileName, dataType="files"):
    if dataType == "files":
        searchString = input("Please enter the filePath, or path thereof: ")
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


def virusScan(fileName):
    # Select either full scan or single scan for file or url
    print("""
===== Virus Scan (VirusTotal) =====
1. Full Scan (All files and URLs)
2. Scan files by Keyword
3. Scan URLs by Keyword
4. Back
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
        else:
            print("Invalid selection, please choose again.\n")


def inputRawImage():
    fileName = chooseImage()
    print(f"{fileName} selected. Processing image..")

    outputFile = f"{fileName}_output.csv"

    # Check if outputFile exists
    if os.path.isfile(outputFile):
        choice = input("Image has been processed before, overwrite? (y/n) ")
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
        selection = showMenu()

        if selection == "1":
            print(displayFiles(outputFile))
        elif selection == "2":
            print(searchFile(outputFile))
        elif selection == "3":
            exportFile(fs_object)
        elif selection == "4":
            print(displayWebHistory(fileName, fs_object))
        elif selection == "5":
            virusScan(fileName)
        elif selection == "6":
            subprocess.Popen("User Manual.pdf", shell=True)
        elif selection == "7":
            webbrowser.open('https://github.com/afiqbusari7/Arcana')
        elif selection == "8":
            print("Exiting the program..")
            exit()
        else:
            print("Invalid selection, please choose again.\n")


def inputFile():
    while True:
        selection = input("\nInput directory of file you would like to scan: ")
        fileName = Path(selection)        
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
            print(tabulate([[selection, verdict]], headers=['File', 'Verdict'], tablefmt='orgtbl'))
            exit()
        else:
            print("File could not be found in directory, please choose again.")


def inputURL():
    while True:
        selection = input("\nInput URL you would like to scan eg. https://www.facebook.com: ")
        # Check if URL is valid
        if validators.url(selection) == True:
            # Process URL
            result = testURL(selection)
            # Add those which are malicious
            if result['malicious'] > 0:
                verdict = 'Malicious'
            else:
                verdict = 'Safe'
                
            # Format table
            print(tabulate([[selection, verdict]], headers=['URL', 'Verdict'], tablefmt='orgtbl'))
            exit()
        else:
            print("URL is in the wrong format, please enter URL again. eg. https://www.facebook.com")


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
        userInput = showInput()

        if userInput == "1":
            inputRawImage()
        elif userInput == "2":
            inputFile()
        elif userInput == "3":
            inputURL()
        elif userInput == "4":
            print("Exiting the program..")
            exit()
        else:
            print("Invalid selection, please choose again4.\n")


if __name__ == "__main__":
    main()
