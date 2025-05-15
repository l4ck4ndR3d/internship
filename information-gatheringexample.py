import json
import socket
import requests
import sys
host = input("Enter the IP or Domain name : ")

try:
        address = requests.get("https://"+host)  # getting the domain website using request.get()
        print("\n",str(address.headers))                # gathering the headers of the particular website
        print("\n********************************************************")
        ip_address = socket.gethostbyname(host)  # getting ip address using the socket.gethostbyname()
        print(f'\nScanning the IP address: {ip_address} ==> {host}')
        rep_two = requests.get("https://ipinfo.io/"+ip_address+"/json") #importing the ipaddress to ipinfo.io website
        resp = json.loads(rep_two.text)                 
        print("\nDomain         : "+resp["ip"])
        print("Location       : "+resp["loc"])
        print("Region         : "+resp["region"])
        print("City           : " + resp["city"])
        print("Country        : "+resp["country"])
        print("Postal         : "+resp["postal"])
        print("Organisation   : " + resp["org"])
        print("TimeZone       : "+resp["timezone"])
        print("Readme         : "+resp["readme"])
        print("\n********************************************************")
        print(resp)                    
except socket.gaierror as e:
        print("Error: Invalid hostname or IP address provided.")
