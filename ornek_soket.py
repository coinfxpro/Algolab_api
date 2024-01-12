from algolab import Backend
from socket import *
import json,time
from config import *

def process_msg(msg):
    try:
        t = msg["type"]
        content = msg["content"]
        print("Type: " + t +"Content: " + content)
    except Exception as e:
        print("Error processing message: ", e)

if __name__ == "__main__":

    algo = Backend(api_key=MY_API_KEY, username=MY_USERNAME, password=MY_PASSWORD, auto_login=True)
    soket = socket(algo.api_key, algo.hash, "T")
    soket.connect()
    while not soket.connected:
        time.sleep(0.05)

    data = {"Type": "T", "Symbols": ["ALL"]}
    soket.send(data)

    i = 0
    while soket.connected:
        data = soket.recv()
        i += 1
        if data:
            try:
                msg = json.loads(data)
                print(msg)
            except:
                print("error 1")
                soket.close()
                break
