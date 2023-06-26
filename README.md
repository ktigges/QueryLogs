# QueryLogs

Example script to query panorama traffic logs with a few parameters and display
the results on the screen.

Files:
	encrypt_api.py	Script encrypts the API key utilized so that it is not
			visible on the file system.  Place the API key in a file called
			api.txt, then run python3 ./encrypt_api.py

			Script will read the API key, and output 2 files that are 
			utilized to derrive the API key, then deletes the api.txt
			file from the system.

			Not super scecure - I'll update a bit later, but at least
			you don't have the API key on the file system for casual
			reading.

	query.py	Main script
			Takes 4 arguments
			Panorama IP
			Number of minutes to go back
			IP address to search
			Port to search (optional)

			Script takes the above arguments, queries the panorama traffic 
			logs and outputs the results.

Note:   You are welcome to modify this to fit your needs, adding different query options, 
	output results etc..  
