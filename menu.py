import os
import pandas as pd
# from virusTotalAPI import testHash, testURL
from processFunctions import processImage, getLoadList, processWebHistory, exportFile


# function for choosing target image
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


# function to display menu options
def showMenu():
    print("""
===== Arcane Functions =====
1. Display Files
2. Keyword Search
3. Export File
4. Process and display Web History
5. Scan for Virus
6. Exit
""")

    # prompts user for menu input
    selection = input("Choose an option: ")
    return selection


# function to display all files in the image
def displayFiles(fileName):
    df = pd.read_csv(fileName)
    return df


# function to search for files containing specific keywords
def searchFile(fileName):
    # prompts user for search input
    searchString = input("Enter search: ")
    print(f"Searching for {searchString}..")

    # display files containing keywords
    df = displayFiles(fileName)
    return df.loc[df['File'].str.contains(searchString, case=False)]


# TODO
# function to display browser history found in the image
def displayWebHistory(fileName, fs_object):
    processWebHistory(fileName, fs_object)

    # check if there is a csv file containing browser history in the image file
    try:
        df = pd.read_csv(f"{fileName}_history.csv", index_col=0)
        return df

    # display error message if browser history file does not exist
    except Exception as e:
        print(f"Exception: {e}")
    return "No Web History found."


# TODO
# function to scan for infected files in the image
def virusScan(fileName):
    print("Scanning Files..")
    file_df = pd.read_csv(f"{fileName}_output.csv")
    # Scan files
    files = []
    for index, row in file_df.iterrows():
        if index > 0:  # Limit testing to one file, due to API constraints
            break
        # Process Hash
        result = testHash(row['SHA256 Hash'])
        # Add those which are malicious
        if result['malicious'] > 0:
            verdict = 'malicious'
        else:
            verdict = 'safe'
        files.append([index, row['File Path'], verdict])

    # scan for unsafe websites found in the browser history
    print("Scanning Websites..")
    url_df = pd.read_csv(f"{fileName}_history.csv", index_col=0)

    urls = []
    for index, row in url_df.iterrows():
        if index > 0:  # Limit testing to one URL, due to API constraints
            break
        # Process URL
        result = testURL(row['URL'])
        # Add those which are malicious
        if result['malicious'] > 0:
            verdict = 'malicious'
        else:
            verdict = 'safe'
        urls.append([index, row['URL'], verdict])

    # Display files and websites which are malicious
    # path for files and url for websites
    print("Files: ")
    print(pd.DataFrame(files, columns=['Index', 'File Path', 'Verdict']))
    print("URLs: ")
    print(pd.DataFrame(urls, columns=['Index', 'URL', 'Verdict']))


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

    fileName = chooseImage()
    print(f"{fileName} selected. Processing image..")

    outputFile = f"{fileName}_output.csv"

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
            print("Exiting the program..")
            exit()
        else:
            print("Invalid selection, please choose again.\n")


if __name__ == "__main__":
    main()
