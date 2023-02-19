import websocket
import json

# Define the WebSocket URL
ws_url = "ws://bagel.htb:5000/"

# Create a new WebSocket object
ws = websocket.WebSocket()

# Connect to the WebSocket server
ws.connect(ws_url)

# Create a dictionary containing the request parameters
order = {"ReadOrder": "orders.txt"}

# Convert the dictionary to a JSON-encoded string
data = json.dumps(order)

# Send the message to the WebSocket server
ws.send(data)

# Wait for a response from the server
result = ws.recv()

# Print the response
print(json.loads(result)['ReadOrder'])

# Close the WebSocket connection
ws.close()
