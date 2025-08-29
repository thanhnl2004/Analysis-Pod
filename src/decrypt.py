import hashlib
import json
from rdflib import Graph, URIRef
from base64 import b64decode, b64encode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

import os
from dotenv import load_dotenv
load_dotenv()

separator = '#'
path_pred = 'path'
iv_pred = 'iv'
session_key_pred = 'sessionKey'
data_pred = 'encData'


def parse_ttl(fname):
    # Parse a .ttl file into a dictionary
    g = Graph()
    g.parse(fname)

    tripleMap = dict()
    for sub, pre, obj in g:
        s = sub.lower() if isinstance(sub, URIRef) else sub
        p = pre.split('#')[-1]
        o = obj.split('#')[-1]
        if s in tripleMap:
            d = tripleMap[s]
            if p in d:
                d[p].add(o)
            else:
                d[p] = [o]
        else:
            tripleMap[s] = {p: [o]}
    return tripleMap


def parse_encrypted_data_ttl(fname):
    # Parse a .ttl file to retrieve values of iv and encData
    # See https://rdflib.readthedocs.io/en/stable/gettingstarted.html for more examples

    g = Graph()
    g.parse(fname)

    iv_b64 = None
    data_b64 = None
        
    for sub, pre, obj in g:
        # print(f'{sub}: ({pre}, {obj})')
        if pre.split(separator)[-1] == iv_pred:
            iv_b64 = obj
        if pre.split(separator)[-1] == data_pred:
            data_b64 = obj
    assert iv_b64 is not None
    assert data_b64 is not None
    return iv_b64, data_b64

def gen_master_key(security_key_str):
    # Generate master key from security key string as per `solidpod`
    return hashlib.sha256(security_key_str.encode('utf-8')).hexdigest()[:32].encode('utf-8')

def decrypt(data_ct, key, iv):
    # CTR mode is also known as segmented integer counter (SIC) mode, as per
    # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
    # It seems the first half of `iv' should be used as `nonce', and the latter half for `initial_value'
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8], initial_value=iv[8:])
    return unpad(cipher.decrypt(data_ct), AES.block_size)
    
def main(master_key, session_key_ct_b64, session_key_iv_b64, data_ct_b64, data_iv_b64):
    # security_key_str = 'YOUR_SECURITY_KEY'
    
    session_key_ct = b64decode(session_key_ct_b64)
    session_key_iv = b64decode(session_key_iv_b64)
    data_ct = b64decode(data_ct_b64)
    data_iv = b64decode(data_iv_b64)

    # Decrypt the session key
    # master_key = gen_master_key(security_key_str)
    session_key_b64 = decrypt(session_key_ct, master_key, session_key_iv)
    session_key = b64decode(session_key_b64)
    
    # Decrypt blood pressure data
    return decrypt(data_ct, session_key, data_iv)


if __name__ == '__main__':
    security_key_str = os.getenv('SECURITY_KEY')
    master_key = gen_master_key(security_key_str)

    # Change this line to point to any available blood pressure file for patient01
    fname = 'blood_pressure_2025-08-19T08-00-00.json.enc.ttl'
    
    # Change these paths to use relative paths to the data directory
    fdatapath = f'data/blood_pressure/patient01/{fname}'
    fkeypath = 'data/blood_pressure/patient01/ind-keys.ttl'

    # Parsing ind-keys.ttl file
    result = parse_ttl(fkeypath)
    keyMap = {v[path_pred][0]: {iv_pred: v[iv_pred][0], session_key_pred: v[session_key_pred][0]} for k, v in result.items() if iv_pred in v}
    fpath = f'healthpod/data/blood_pressure/{fname}'
    session_key_ct_b64 = keyMap[fpath][session_key_pred]
    session_key_iv_b64 = keyMap[fpath][iv_pred]

    # Parse blood pressure .ttl file
    result = parse_ttl(fdatapath)
    dataKey = list(result.keys())[0]
    dataMap = {iv_pred: result[dataKey][iv_pred][0], data_pred: result[dataKey][data_pred][0]}
    data_ct_b64 = dataMap[data_pred]
    data_iv_b64 = dataMap[iv_pred]

    # Decrypt the data
    data = main(master_key, session_key_ct_b64, session_key_iv_b64, data_ct_b64, data_iv_b64)
    
    # Parse the JSON data
    try:
        # Decode binary data to string and parse JSON
        json_str = data.decode('utf-8')
        parsed_data = json.loads(json_str)
        
        # Extract individual fields
        timestamp = parsed_data.get('timestamp')
        responses = parsed_data.get('responses', {})

        systolic = responses.get('systolic')
        diastolic = responses.get('diastolic') 
        heart_rate = responses.get('heart_rate')
        notes = responses.get('notes')
        
        # Display the extracted data
        print('Decrypted and parsed data:')
        print(f'Timestamp: {timestamp}')
        print(f'Systolic: {systolic} mmHg')
        print(f'Diastolic: {diastolic} mmHg') 
        print(f'Heart Rate: {heart_rate} bpm')
        print(f'Notes: "{notes}"')
        
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f'Error parsing JSON data: {e}')
        print('Raw decrypted data:')
        print(data)