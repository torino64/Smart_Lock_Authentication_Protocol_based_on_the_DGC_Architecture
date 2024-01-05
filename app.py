from fastapi import FastAPI, HTTPException
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from pymongo import MongoClient
import random
import base64
from pydantic import BaseModel
from Symetric import SymmetricCrypto
from hashlib import sha256



app = FastAPI()
group = PairingGroup('SS512')

# MongoDB setup
client = MongoClient('localhost', 27017)  # Connect to local MongoDB instance
db = client['authentication_db']   
smart_lock_parameter = db['smart_lock_parameter']        # Use 'authentication_db' database
keys_collection = db['keys']               # Collection for keys
tree_collection = db['tree']               # Tree Structure Collection
traces_collection = db['traces']
params_collection = db['params']           # Collection for params
server_id = str(99599599)
crypto = SymmetricCrypto()
ms = group.random(ZR)
password = "5a88740AD4"
key = crypto.generate_key(password)

# Initialization Endpoint
@app.get("/initialize/{n}")
def initialize(n: int):
    g2 = group.random(G2)
    # Generate private and public keys for the server and store in MongoDB
    sk_server = group.random(ZR)
    pk_server = g2 ** sk_server
    g_server = group.random(G1)
    
    keys_collection.insert_one({
        'ID': server_id,
        'g': group.serialize(g_server),
        'sk': str(sk_server),
        'pk': group.serialize(pk_server)
    })
    l = group.random(ZR)
    ID_server = group.init(ZR, int(server_id))
    sigma_0_prime = (g_server ** (1 / (sk_server + ID_server))) ** l
    sigma_0_double_prime = (sigma_0_prime ** (-1*ID_server)) * (g_server ** l)
    # Store sigma_0' and sigma_0'' in the smart_lock_parameter collection
    smart_lock_parameter.insert_one({
        'sigma_0_prime': group.serialize(sigma_0_prime),
        'sigma_0_double_prime': group.serialize(sigma_0_double_prime)
    })
    for _ in range(1, n+1):  # Starting from 1 as 0 is reserved for the server
        sk = group.random(ZR)
        pk = g2 ** sk
        ID = group.random(ZR)
        g = group.random(G1)

        keys_collection.insert_one({
            'ID': str(ID),
            'g': group.serialize(g),
            'sk': str(sk),
            'pk': group.serialize(pk)
        })

    params = {
        "q": str(group.order()),
        "G1": str(G1),
        "G2": str(G2),
        "GT": str(G1 * G2),
        "e": str(pair),
        "g2": group.serialize(g2)
    }
    # Store params in MongoDB
    params_collection.insert_one(params)
    return {"status": "initialized"}

@app.get("/register_smart_lock")
def register_smart_lock():

    # Retrieve the parameters from the database
    smart_lock_params = smart_lock_parameter.find_one()

    if not smart_lock_params:
        raise HTTPException(status_code=404, detail="Smart lock parameters not found")

    # Extract sigma_0_prime and sigma_0_double_prime from the database entry
    sigma_0_prime = smart_lock_params.get("sigma_0_prime")
    sigma_0_double_prime = smart_lock_params.get("sigma_0_double_prime")

    # Return the retrieved values
    return {
        "sigma_0_prime": base64.b64encode(sigma_0_prime),
        "sigma_0_double_prime": base64.b64encode(sigma_0_double_prime)
    }

class MasterData(BaseModel):
    sigma0Prime: str
    sigma0DoublePrime: str

@app.post("/register_master")
def register_master(master_data: MasterData):
    # Fetch parameters
    params = params_collection.find_one({})
    
    # Convert received string parameters back to group elements
    sigma_prime_bytes = base64.b64decode(master_data.sigma0Prime)
    sigma_double_prime_bytes = base64.b64decode(master_data.sigma0DoublePrime)
    sigma_prime = group.deserialize(sigma_prime_bytes)
    sigma_double_prime = group.deserialize(sigma_double_prime_bytes)

    # Fetch the server's pk_0
    server_data = keys_collection.find_one({'ID': server_id})
    if not server_data:
        raise HTTPException(status_code=400, detail="Server data not found in keys collection")
    pk_0 = group.deserialize(server_data['pk'])
    g2 = group.deserialize(params['g2'])
    # Validate the equation e(σ'' , g2) = e(σ' , pk_0)
    if pair(sigma_double_prime, g2) != pair(sigma_prime, pk_0):
        raise HTTPException(status_code=400, detail="Invalid parameters")
    
    # Fetch a random user's data from keys_collection
    count = keys_collection.count_documents({})
    random_index = random.randint(0, count-1)
    master_data = keys_collection.find().skip(random_index).limit(1).next()

    if not master_data:
        raise HTTPException(status_code=400, detail="Could not fetch random data from keys collection")

    # Compute sigma_1
    g = group.deserialize(master_data['g'])
    sk = group.init(ZR, int(master_data['sk']))
    ID = group.init(ZR, int(master_data['ID']))
    sigma_1 = g ** (1 / (sk + ID))

    # Generate a session ID for the master
    session_ID = group.random(ZR)

    # Create the root node for the master in the tree collection
    tree_collection.insert_one({
        'ID': master_data['ID'],
        'g': master_data['g'],
        'sk': master_data['sk'],
        'pk': master_data['pk'],
        'parent': None,  # Master has no parent as it's the root
        'session_ID': str(session_ID),
        'ID_fils': None  # Child ID set to None for now
    })

    traces_collection.insert_one({"trace": "Register : 12:40"})

    # Delete the fetched data from keys_collection
    #keys_collection.delete_one({'ID': master_data['ID']})
    payload = master_data['ID'] + '|' + group.serialize(sigma_1).decode()
    payload_bytes = payload.encode()
    encrypted_payload = crypto.encrypt(payload_bytes, key)
    return {"session_ID":str(session_ID), "payload": str(encrypted_payload), "q": params["q"], "g": base64.b64encode(master_data["g"])}


@app.get("/ask_authentification_master")
def ask_authentification_master():
    return {"ms":str(ms)}

class MasterDataAuth(BaseModel):
    sigmapPrime: str
    sigmapDoublePrime: str
    cp: str
    Sap: str
    SIDp: str
    NT: str

@app.post("/authentification_master")
def authentification_master(master_data_auth: MasterDataAuth):
    # Deserialize group elements
    sigma_p_prime = group.deserialize(base64.b64decode(master_data_auth.sigmapPrime))
    sigma_p_double_prime = group.deserialize(base64.b64decode(master_data_auth.sigmapDoublePrime))
    cp = int(master_data_auth.cp)
    Sap = int(master_data_auth.Sap)
    SIDp = int(master_data_auth.SIDp)
    NT = int(master_data_auth.NT)

    master_data = tree_collection.find_one({})
    gp = group.deserialize(master_data['g'])
    
    # Fetch g2 and server's pk from the database
    params = params_collection.find_one({})
    g2 = group.deserialize(params['g2'])
    server_data = keys_collection.find_one({'ID': server_id})
    pk_s = group.deserialize(server_data['pk'])

    # Calculate T_s (without modulus q)
    T_s = (sigma_p_double_prime ** cp) * (gp ** Sap) * (sigma_p_prime ** SIDp)
    # Calculate c_s^ (hash)
    hash_input = group.serialize(sigma_p_double_prime) + group.serialize(T_s) + group.serialize(ms)
    c_s_hash = int(sha256(hash_input).hexdigest(), 16) % group.order()
    # Perform verifications
    if pair(sigma_p_double_prime, g2) != pair(sigma_p_prime, pk_s) or cp != c_s_hash:
        raise HTTPException(status_code=400, detail="Authentication failed")
    

    return {"status": "Authentication successful"}

# This would run the FastAPI app. In production, you'd use something like Uvicorn to serve the app.
if __name__ == "__main__":
     import uvicorn
     uvicorn.run(app, host="0.0.0.0", port=8000)
