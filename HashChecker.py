# ----------------------------------------------------------------------------------------------------------------------
#   HashChecker.py                                             Author: Wildcat95
#
#   This program has two main functions. These can be used independent of one another.
#
#   1st function: A user can select a file from their system and have md5, sha-1, sha-256, sha-512, sha-3, blake2
#       hashes created for this file. These hashes are labeled and placed into a file called 'file_hashes.txt'
#       in a location of the user's choosing.
#
#   2nd function: The user can use this program to check hashes against VirusTotal's database. Results of the search
#                   are placed into a file 'hash_check_result.txt' in a location of the user's choosing.
#                   The file will indicate if the hash has been flagged as 'malicious' or 'not malicious'.
#       A user is presented with 3 entry boxes.
#           Box 1: Enter a hash
#           Box 2: Enter your API key
#           Box 3: Enter the complete file path where you want your results placed.
#
# Readme located at: https://github.com/Wildcat95/Hash-Checker.git
# ----------------------------------------------------------------------------------------------------------------------
import requests
import tkinter as tk
import hashlib
from tkinter import filedialog
import tkinter.messagebox


# Function to check a hash against virustotal.com
def check_hash():
    user_hash = hash_entry.get()
    api_key = key_entry.get()

    # Parameters for virustotal (api_key and user_hash)
    params = {'apikey': api_key, 'resource': user_hash}

    # Get a response from virustotal based on the user_hash and using the provided api_key
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    result = response.json()
    is_malicious = result.get('positives', 0) > 0
    directory = dir_entry.get()

    # Create the file 'hash_check_result'. If this already exists, the new hash is added to the file on a new line
    with open(f'{directory}/hash_check_result.txt', 'a') as file:
        file.write(f'\nThe hash {user_hash} is {"malicious" if is_malicious else "not malicious"}')

    # Display the message in the window
    tkinter.messagebox.showinfo('Hash Check Result',
                                f'The hash {user_hash} is {"malicious" if is_malicious else "not malicious"}.'
                                f'\n\nResult stored at: {directory}/hash_check_result.txt')


# Function to allow the user to select a file from their system.
# This is achieved by clicking on the 'Select Suspicious File' button.
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as file:
            content = file.read()
            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
            sha512_hash = hashlib.sha512(content).hexdigest()
            sha3_hash = hashlib.sha3_256(content).hexdigest()
            blake2_hash = hashlib.blake2b(content).hexdigest()
            directory = filedialog.askdirectory()
            hash_file_path = f'{directory}/file_hashes.txt'

            # Creates MD5, SHA-1, SHA-256, SHA-512, SHA-3 and Blake2 hashes of the user specified file.
            # Stores these hashes in the user specified file (hash_file_path)
            with open(hash_file_path, 'w') as hash_file:
                hash_file.write(
                    f'MD5: {md5_hash}\nSHA-1: {sha1_hash}\nSHA-256: {sha256_hash}\nSHA-512:'
                    f' {sha512_hash}\nSHA-3: {sha3_hash}\nBlake2: {blake2_hash}')
                tkinter.messagebox.showinfo('Hash File Stored', f'The hash file has been stored at: {hash_file_path}')


# Clears the program to enter new information. This is achieved by clicking the 'Reset' button.
def reset_fields():
    hash_entry.delete(0, 'end')
    key_entry.delete(0, 'end')
    dir_entry.delete(0, 'end')


# Closes the program. This is achieved by clicking the 'Close' button.
def close_window():
    window.destroy()


# Create the tkinter window
window = tk.Tk()
window.title("<<Hash Checker>>")

# Create a button to select the file and generate hashes
top_label = tk.Label(window)
top_label.pack(pady=10)
file_button = tk.Button(window, text="Select Suspicious File", pady=10, padx=10, command=select_file)
intro_label = tk.Label(window, text="Select a file from your system to create hashes:", font=('Calibri', 20, 'bold'))
intro_label.pack(padx=10)
altintro_label = tk.Label(window, text="(Hashes created: md5, sha-1, sha-256, sha-512, sha-3, blake2)",
                          font=('Calibri', 12, 'italic'))
altintro_label.pack()
file_button.pack(padx=10, pady=10)

# Create input fields and labels
intro2_label = tk.Label(window, text="Search Virustotal for specific hashes\nProvided you have an API key",
                        font=('Calibri', 20, 'bold'))
blank_label = tk.Label(window, bd=5)
hash_label = tk.Label(window,
                      text="Enter the hash you want to look up:"
                           "\n(Options: md5, sha-1, sha-256, sha-512, sha-3, blake2)",
                      font=('Calibri', 12, 'bold'))
hash_entry = tk.Entry(window, bd=5)
key_label = tk.Label(window, text="Enter your VirusTotal API key: ", font=('Calibri', 12, 'bold'))
key_entry = tk.Entry(window, bd=5)
dir_label = tk.Label(window, text="Where would you like your .txt file stored? \n(Provide complete path): ",
                     font=('Calibri', 12, 'bold'))
dir_entry = tk.Entry(window, bd=5)
sep_label = tk.Label(window, text="-------------------------------------------------------------------------------",
                     font=('Calibri', 20, 'bold'))
sep_label2 = tk.Label(window, text="-------------------------------------------------------------------------------",
                      font=('Calibri', 20, 'bold'))

# Create a button to trigger the hash check ('check_hash' function)
check_button = tk.Button(window, text="Check Hash", pady=10, padx=10, command=check_hash)

# Placement the input boxes, labels (lines of text), and buttons in the tkinter window
# Placement in this order is how it will appear in the tkinter window
sep_label.pack()
intro2_label.pack()
blank_label.pack()
hash_label.pack(padx=10, pady=10)
hash_entry.pack(padx=10)
key_label.pack(padx=10, pady=10)
key_entry.pack(padx=10)
dir_label.pack(padx=10, pady=10)
dir_entry.pack(padx=20)
check_button.pack(padx=10, pady=10)
sep_label2.pack()

reset_button = tk.Button(window, text="Reset", pady=10, padx=44, command=reset_fields)
reset_button.pack(padx=10, pady=20)

close_button = tk.Button(window, text="Close", pady=10, padx=50, command=close_window)
close_button.pack(padx=10, pady=10)

# Run the tkinter main loop
window.mainloop()
