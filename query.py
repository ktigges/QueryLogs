# Author.....: Kevin Tigges
# Script Name: query.py
# Desc.......: Script to query Palo Alto Panorama logs 
#              Yes I should turn the encrypt tools into a module - I will do this later
# 
#
# Last Updates: 6/13/2023
# v001
#
import requests
# Uncomment pdb to set debug trace
import pdb
from cryptography.fernet import Fernet
import os
import time
import base64
import os
import argparse
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
import sys
import argparse

# Don't print the SSL warnings - as we disabled them.  
# You may change the code to validate the SSL cert if that meets your requirements
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def get_api():
# Password is encrypted so it is not present in this script and is read from 2 files containing the encrypted password and key
# There is a script called encryptpwd.py that should be used to generate the encrypted password to be used prior to using this script
#
# Place the password in a file called pwd.txt (This will be deleted once the encrypted password is generated)
# Run the script - python3 ./encryptpwd.py
# 2 files will be generated that should be kept in the script directory and will be utilized to authenticate below
#
# read encrypted pwd and convert into byte
#
    cwd = './'
    with open('./apipass.txt') as f:
        apipwd = ''.join(f.readlines())
        encpwdbyt = bytes(apipwd, 'utf-8')
    f.close()

    # read key and convert into byte
    with open('./apikey.txt') as f:
        refKey = ''.join(f.readlines())
        refKeybyt = bytes(refKey, 'utf-8')
    f.close()

    # use the key and decrypt the password

    keytouse = Fernet(refKeybyt)
    # Convert the password from byte to Ascii
    api_key = (keytouse.decrypt(encpwdbyt)).decode('ASCII')
    return api_key.strip()


def returnheader(api_key):
# Functions returns the "Authorization Basic" header with the userid:password encoded in base64
#
    #authstr = user_id + ":" + user_password
    #bytestr = authstr.encode('ascii')
    #authb64 = base64.b64encode(bytestr)
    #authb64 = str(authb64, encoding='utf-8')

    header = { 'X-PAN-KEY' : f'{api_key}'}
    return(header)


def getjobid(txtresponse):
# response will have the job ID after the <job> tag
# Loop through the response after the <job> tag until the end tag starts (</job>) grabbing out the job number
#
    i = txtresponse.find('<job>')
    # what position is the <job> string at?
    jobid = ""
    # Start at the position 5 over from the tag
    i = i + 5
    # while the incrementer is less than the total length
    while i < len(txtresponse):
        #if we have hit the end of job tag (<) then break out - we are done
        if (txtresponse[i] == "<"):
            break
        #otherwise add the jobid character to the end result
        else:
            jobid = jobid + txtresponse[i]
        #increment the counter
        i = i + 1
    return(jobid)

def query_logs(api_key, panorama_ip, start_time, end_time, ip1, dport):
    # Build the API request URL
    # pdb.set_trace()
    #start_time = '2023/06/18 14:00:00'
    #end_time = '2023/06/18 14:30:00'
    if (dport == 'all'):
        query = f"(receive_time geq '{start_time}' and receive_time leq '{end_time}') and (src eq {ip1} or dst eq {ip1})"
    else:
        query = f"(receive_time geq '{start_time}' and receive_time leq '{end_time}') and (src eq {ip1} or dst eq {ip1}) and dport eq {dport}"
    
    url = f'https://{panorama_ip}/api/?type=log&log-type=traffic&nlogs=1000&query={query}'
    # headers = {'X-PAN-KEY': api_key}
    # Build the XML query payload
    # Send the API request
    # print(returnheader(api_key))
    # pdb.set_trace()
    
        response = requests.post(url, headers = returnheader(api_key), verify=False)
        # Check the API response status as well as the code returned.  19 will be job enqueued, anything else we don't want to run as there is an error
    if (response.status_code == 200 and str(response.content).find('code="19"')) > 0:
        return(response)
    else:
        print(f'Error occurred. Status code: {response.status_code}, Response content: {response.content}')
    return(response)
   
def get_status(api_key, panorama_ip, jobid):
    status = 'ACT'
    print("Checking Job Status....")

    while status == 'ACT':
        dot = '*'
        print(dot, end= "", flush=True)
        url =  f'https://{panorama_ip}/api/?type=log&log-type=traffic&action=get&job-id={jobid}'
        response = requests.get(url, headers = returnheader(api_key), verify=False)
        xml_string = str(response.content, 'utf-8')
        xml_string = xml_string.replace('\n', '')
        root = ET.fromstring(xml_string)
        element = root.findall('result/job')
        for job in element:
            status = job.find('status').text
            time.sleep(2)
       # pdb.set_trace()
    return(xml_string)

def print_logs(xml_string):
    # Parse the XML response
        root = ET.fromstring(xml_string)

        # Extract the log entries - they will be in the <entry> tag
        entries = root.findall('.//entry')

        # Process and print the log entries

        print(f"{'Time':<20s} {'Source':<18s} {'Dest':<18s} {'FromZone':15s} {'ToZone':<15s} {'S_Port':<6s} {'D_Port':<6s} {'Proto':<5s} {'Action':<6s} {'Bytes':<8s}") 
        print("\n")
        for e in entries:
            # Extract the desired fields from the entry
            #
            # Source = 15
            # Dest = 15
            # rule = Variable
            # fromzone = 15
            # tozone = 15
            # dport = 5
            # sport = 5
            # protocol = 5
            # action = 6
            # bytes = 8
            time = e.find('receive_time').text
            source = e.find('src').text
            dest = e.find('dst').text
            rule = e.find('rule').text
            fromzone = e.find('from').text
            tozone = e.find('to').text
            dport = e.find('dport').text
            sport = e.find('sport').text
            protocol = e.find('proto').text
            action = e.find('action').text
            bytes = e.find('bytes').text
            # Print the extracted fields
            print(f"{time:<20s} {source:<18s} {dest:<18s} {fromzone:<15s} {tozone:<15s} {sport:<6s} {dport:<6s} {protocol:<5s} {action:<6s} {bytes:<8s}")


def main(panorama_ip, minutes, ip1, port):
    api_key = get_api()
    panorama_ip = "192.168.254.5"

    # Set the query parameters

    # Get the start / end times based on minutes sent, and convert to string
    start_time = datetime.now() - timedelta(minutes = minutes)
    end_time = datetime.now()
    start_time = start_time.strftime("%Y/%m/%d %H:%M:%S")
    end_time = end_time.strftime("%Y/%m/%d %H:%M:%S")
 
    # Static Values for testing only
    #start_time = '2023/06/12 08:00:00'
    #end_time = '2023/06/12 08:05:59'
    #ip1 = "192.168.254.112"
    #ip2 = "any"
    #port = "any"

    jobid = ""

    try:
     
       response = query_logs(api_key, panorama_ip, start_time, end_time, ip1, port)
       jobid = getjobid(response.text)

       print('Query Queued : Job ID ' + jobid + '\n')
       xml_string = get_status(api_key, panorama_ip, jobid)
       print_logs (xml_string)
       
    except Exception as e:
        print(f"Failed to query logs : {str(e)}")

if __name__ == "__main__":
#    # Create the Parser for the command line arguments
#    # Panorama IP, Number of Minuites, IP1, Port
    p = argparse.ArgumentParser(description = 'Script to query panorama traffic logs')
    p.add_argument('panorama_ip', type=str, help="Enter the Panorama IP")
    p.add_argument('minutes', type=int, help="Enter the number of minutes to show")
    p.add_argument('ip', type=str, help="Enter IP Address to search")
    p.add_argument('--PORT', '-P', type=str, default = "all", required=False, help="Enter Port to search ('blank' for all)")
    args = p.parse_args()
    main(args.panorama_ip, args.minutes, args.ip, args.PORT)
    



