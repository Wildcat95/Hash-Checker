**Readme**

This program has two main functions:

   1st function: 'Select a file from your system to create hashes:'

	By selecting the 'Select Suspicious File' button at the top of the window, the user is given
		the option to select a file on their system.

	After selecting the file and clicking 'Open', another window pops up.

	This new window is where the user will select the location they want their created 'file_hashes.txt' file,
		with hashes included, saved to.

	After clicking 'Open', the user is presented with a dialog box that tells the user
		where the 'file_hashes.txt' file with hashes was stored.

	A user can open this file on their system to find md5, sha-1, sha-256, sha-512, sha-3, blake2
		hashes of the file they selected.



   2nd function: 'Search VirusTotal for specific hashes'

       A user is presented with 3 entry boxes.

           Box 1: 'Enter the hash you want to look up:'
		This can be any md5, sha-1, sha-256, sha-512, sha-3, blake2 hash

           Box 2: 'Enter your VirusTotal API key:'
		Enter your API key to allow the program to interact with VirusTotal.com

           Box 3: 'Where would you like your .txt file stored?'
		This is where the user inputs the complete path the results of the hash check
			will be stored. This is stored in a created file named 'hash_check_result.txt'
		If 'hash_check_result.txt' already exists in the specified location, the file will
			be updated with hashes each time the user completes a new search.
		Each hash will be labeled as 'malicious' or 'not malicious'.

	After entering the above information, the user will click the 'Check Hash' button.
		This will actually perform the search and compare the input hash
			to the VirusTotal database. This is when the 'hash_check_result.txt' file is created.
		'hash_check_result.txt' will now be stored in the location of the user's choosing
			and include the hash and if it was malicious or not.

The 'Reset' button is an easy way to clear the information the user has previously typed in to the program.

The 'Close' button will close the program.







	The user can use this program to check hashes against VirusTotal's database.
		Results of the search are placed into a file 'hash_check_result.txt' in a
		location of the user's choosing. The file will indicate if the hash has
		been flagged as 'malicious' or 'not malicious'.