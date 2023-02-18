import requests
from bs4 import BeautifulSoup

# Starting URL
url = 'http://13.36.37.184:45260'

# Flag variable to indicate if the correct path is found
flag = False

# list of path values
paths = []

while True:
    # getting the page
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    print(f'Getting page from: {url}')
    
    # find the path on the page
    links = soup.find_all('a')
    paths = [link.get('href') for link in links if 'path=' in link.get('href')]
    
    # if no path found break the loop
    if not paths:
        print(f"The flag is: {response.text}")
        break
    print(f'Found {len(paths)} possible paths: {paths}')
    
    # iterate through all possible path values
    for path in paths:
        # Construct the URL with the current path value
        url = 'http://13.36.37.184:45260/' + path

        # Send a GET request to the URL
        response = requests.get(url)
        
        # If we hit a dead end, try the other path
        if "nope" in response.text:
            print("Sorry, you have reached a dead end. Please retry")
            paths.remove(path)
            url = 'http://13.36.37.184:45260' + paths[0]
            continue

        # Check the response for the flag
        if "sabr{" in response.text:
            print(f"The flag is: {response.text}")
            flag = True
            break
        else:
            print(f'Trying path: {path}...')
