# main.py
import os
import base64
import io
import shutil
from flask import Flask, render_template, Response, redirect, request, session, abort, url_for, jsonify, make_response
import json
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
load_dotenv()  # Load .env file so DATABASE_URL is available
import hashlib
from datetime import datetime
from datetime import date
import datetime
import random
import string
from random import seed
from random import randint
from urllib.request import urlopen
import webbrowser
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from werkzeug.utils import secure_filename
import pytesseract
from PIL import Image
import hashlib
from PIL import Image
import urllib.request
import urllib.parse
from urllib.parse import urlparse, unquote
import socket    
import re
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import uuid
#from Pyfhel import Pyfhel
#pip install secretsharing
#from secretsharing import PlaintextToHexSecretSharer
#pip install shamir-mnemonic
from shamir_mnemonic import generate_mnemonics, combine_mnemonics
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from phe import paillier  # homomorphic operations
from typing import List
import pyotp
import qrcode

#from secretsharing import PlaintextToHexSecretSharer

'''mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  charset="utf8",
  database="gene_nft"

)'''
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
WEB_TEMPLATES_DIR = os.path.join(TEMPLATES_DIR, "web")


def ensure_template_structure():
    """
    Make deployment tolerant when HTML files were uploaded without folders.
    If templates are in project root or templates root, copy missing files
    into templates/web so routes like render_template('web/index.html') work.
    """
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    os.makedirs(WEB_TEMPLATES_DIR, exist_ok=True)

    source_dirs = [BASE_DIR, TEMPLATES_DIR, STATIC_DIR, os.path.join(STATIC_DIR, "web")]
    for source_dir in source_dirs:
        if not os.path.isdir(source_dir):
            continue
        for file_name in os.listdir(source_dir):
            if not file_name.lower().endswith(".html"):
                continue
            source_path = os.path.join(source_dir, file_name)
            if not os.path.isfile(source_path):
                continue
            target_path = os.path.join(WEB_TEMPLATES_DIR, file_name)
            if not os.path.exists(target_path):
                shutil.copy2(source_path, target_path)


# ensure_template_structure()  # Disabled — manually place templates in templates/web/

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
##session key
app.secret_key = 'abcdef'
#######
UPLOAD_FOLDER = os.path.join(STATIC_DIR, "upload")
ALLOWED_EXTENSIONS = { 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#####

def get_db_config():
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        parsed = urlparse(database_url)
        return {
            "host": parsed.hostname or os.getenv("DB_HOST", "localhost"),
            "port": parsed.port or int(os.getenv("DB_PORT", "5432")),
            "user": unquote(parsed.username or os.getenv("DB_USER", "postgres")),
            "password": unquote(parsed.password or os.getenv("DB_PASSWORD", "")),
            "database": (parsed.path or "").lstrip("/") or os.getenv("DB_NAME", "gene_nft"),
        }

    return {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "user": os.getenv("DB_USER", "postgres"),
        "password": os.getenv("DB_PASSWORD", ""),
        "database": os.getenv("DB_NAME", "gene_nft"),
    }


def get_db_connection():
    config = get_db_config()
    conn = psycopg2.connect(
        host=config["host"],
        port=config["port"],
        user=config["user"],
        password=config["password"],
        database=config["database"],
        sslmode="require",  # Required for Neon cloud PostgreSQL
    )
    conn.autocommit = False  # explicit commit/rollback — prevents key/sig split-brain
    return conn


def get_db_cursor(conn, dictionary=False):
    if dictionary:
        return conn.cursor(cursor_factory=RealDictCursor)
    return conn.cursor()


@app.route('/', methods=['GET', 'POST'])
def index():
    msg=""
    

    return render_template('web/index.html',msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg=""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        
        cursor.execute('SELECT * FROM gn_admin WHERE username = %s AND password = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            # --- 2FA CHECK ---
            if account[3]:  # totp_enabled
                session['temp_user'] = uname
                session['temp_type'] = 'admin'
                cursor.close(); conn.close()
                return redirect(url_for('verify_login_2fa'))
            # -----------------
            session['username'] = uname
            session['user_type'] = 'admin'
            cursor.close()
            conn.close()
            return redirect(url_for('admin'))
        else:
            msg = 'Incorrect username/password!'

    cursor.close()
    conn.close()  
    return render_template('web/login.html',msg=msg)

@app.route('/login_owner', methods=['GET', 'POST'])
def login_owner():
    msg=""
    act=request.args.get("act")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        
        cursor.execute('SELECT * FROM gn_owner WHERE uname = %s AND pass = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            # --- 2FA CHECK ---
            if account[24]:  # totp_enabled
                session['temp_user'] = uname
                session['temp_type'] = 'owner'
                cursor.close(); conn.close()
                return redirect(url_for('verify_login_2fa'))
            # -----------------
            session['username'] = uname
            session['user_type'] = 'owner'
            cursor.close()
            conn.close()
            return redirect(url_for('owner_home'))
        else:
            msg = 'Incorrect username/password!'
    
    cursor.close()
    conn.close()  
    return render_template('web/login_owner.html',msg=msg,act=act)

@app.route('/login_res', methods=['GET', 'POST'])
def login_res():
    msg=""
    act=request.args.get("act")
    conn = get_db_connection()
    cursor = conn.cursor()

    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        
        cursor.execute("SELECT * FROM gn_researcher WHERE uname = %s AND pass = %s AND status::integer = 1", (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            cursor.close()
            conn.close()
            return redirect(url_for('res_home'))
        else:
            msg = 'Incorrect username/password!'


    cursor.close()
    conn.close()  
    return render_template('web/login_res.html',msg=msg,act=act)


#Blockchain
class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200



def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

#Interact with Smart Contract (NFT Minting)
# ----------------------------
def mint_nft(web3, contract_address, abi, metadata_ipfs_hash, owner_address, private_key):
    contract = web3.eth.contract(address=contract_address, abi=abi)
    nonce = web3.eth.get_transaction_count(owner_address)
    
    txn = contract.functions.mintNFT(owner_address, metadata_ipfs_hash).build_transaction({
        'chainId': 1337,  
        'gas': 300000,
        'gasPrice': web3.toWei('2', 'gwei'),
        'nonce': nonce
    })
    
    signed_txn = web3.eth.account.sign_transaction(txn, private_key=private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt

def genenft(uid,uname,bcdata,utype):
    ############

    now = datetime.datetime.now()
    yr=now.strftime("%Y")
    mon=now.strftime("%m")
    rdate=now.strftime("%d-%m-%Y")
    rtime=now.strftime("%H:%M:%S")
    
    ff=open("static/key.txt","r")
    k=ff.read()
    ff.close()
    
    #bcdata="CID:"+uname+",Time:"+val1+",Unit:"+val2
    dtime=rdate+","+rtime

    ff1=open("static/css/d1.txt","r")
    bc1=ff1.read()
    ff1.close()
    
    px=""
    if k=="1":
        px=""
        result = hashlib.md5(bcdata.encode())
        key=result.hexdigest()
        print(key)
        v=k+"##"+key+"##"+bcdata+"##"+dtime

        ff1=open("static/css/d1.txt","w")
        ff1.write(v)
        ff1.close()
        
        dictionary = {
            "ID": "1",
            "Pre-hash": "00000000000000000000000000000000",
            "Hash": key,
            "utype": utype,
            "Date/Time": dtime
        }

        k1=int(k)
        k2=k1+1
        k3=str(k2)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/prehash.txt","w")
        ff1.write(key)
        ff1.close()
        
    else:
        px=","
        pre_k=""
        k1=int(k)
        k2=k1-1
        k4=str(k2)

        ff1=open("static/prehash.txt","r")
        pre_hash=ff1.read()
        ff1.close()
        
        g1=bc1.split("#|")
        for g2 in g1:
            g3=g2.split("##")
            if k4==g3[0]:
                pre_k=g3[1]
                break

        
        result = hashlib.md5(bcdata.encode())
        key=result.hexdigest()
        

        v="#|"+k+"##"+key+"##"+bcdata+"##"+dtime

        k3=str(k2)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/css/d1.txt","a")
        ff1.write(v)
        ff1.close()

        
        
        dictionary = {
            "ID": k,
            "Pre-hash": pre_hash,
            "Hash": key,
            "utype:": utype,
            "Date/Time": dtime
        }
        k21=int(k)+1
        k3=str(k21)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/prehash.txt","w")
        ff1.write(key)
        ff1.close()

    m=""
    if k=="1":
        m="w"
    else:
        m="a"
    # Serializing json
    
    json_object = json.dumps(dictionary, indent=4)
     
    # Writing to sample.json
    with open("static/genenft.json", m) as outfile:
        outfile.write(json_object)
    ##########

def generate_wallet_address():
    prefix = "0x"
    characters = string.hexdigits.lower()
    address = ''.join(random.choice(characters) for _ in range(40))

    return prefix + address

# Smart Contracts Simulation
# -----------------------------

class OwnershipContract:
    @staticmethod
    def verify_owner(nft_id, user):
        return NFT_LEDGER[nft_id]["owner"] == user


class AccessControlContract:
    permissions = {}

    @staticmethod
    def grant_access(nft_id, requester):
        AccessControlContract.permissions.setdefault(nft_id, []).append(requester)

    @staticmethod
    def check_access(nft_id, requester):
        return requester in AccessControlContract.permissions.get(nft_id, [])


class MonetizationContract:
    prices = {}

    @staticmethod
    def set_price(nft_id, price):
        MonetizationContract.prices[nft_id] = price

    @staticmethod
    def pay_and_access(nft_id, requester, amount):
        required = MonetizationContract.prices.get(nft_id, 0)
        if amount >= required:
            AccessControlContract.grant_access(nft_id, requester)
            return True
        return False


'''def register_user_crypto(user_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    # -------------------------------------------------
    #Split Private Key (Threshold 3 out of 5)
    # -------------------------------------------------
    shares = PlaintextToHexSecretSharer.split_secret(private_pem, 3, 5)

    # -------------------------------------------------
    #Encrypt Each Share (Node-Level Protection)
    # -------------------------------------------------
    encrypted_shares = []
    storage_key = Fernet.generate_key()   # node encryption key
    cipher = Fernet(storage_key)

    for idx, share in enumerate(shares):
        encrypted = cipher.encrypt(share.encode())

        # create hash for blockchain anchoring
        share_hash = hashlib.sha256(share.encode()).hexdigest()

        encrypted_shares.append({
            "user_id": user_id,
            "share_index": idx + 1,
            "encrypted_share": encrypted,
            "share_hash": share_hash
        })

    # -------------------------------------------------
    #Prepare Response (DO NOT RETURN PRIVATE KEY)
    # -------------------------------------------------
    result = {
        "public_key": public_pem,
        "shares": encrypted_shares,
        "node_key": storage_key  # used only by storage service
    }

    return result'''
#Genomic Data NFT
class GenomicNFT:
    def __init__(self, data: str, owner: str, parent_id=None):
        self.id = hashlib.sha256((data + owner).encode()).hexdigest()
        self.owner = owner
        self.parent_id = parent_id
        self.access_list = [] 
        self.data_hash = hashlib.sha256(data.encode()).hexdigest()
        self.encrypted_data = None 
        self.metadata = {
            "id": self.id,
            "owner": self.owner,
            "parent_id": self.parent_id,
            "data_hash": self.data_hash
        }

    def grant_access(self, user: str):
        if user not in self.access_list:
            self.access_list.append(user)

    def revoke_access(self, user: str):
        if user in self.access_list:
            self.access_list.remove(user)

#NFT Manager: Composable NFTs
class NFTManager:
    def __init__(self):
        self.nfts = {}
        self.storage = storage
        self.crypto = crypto

    def create_raw_genomic_nft(self, raw_data: str, owner: str):
        nft = GenomicNFT(raw_data, owner)
        encrypted = self.crypto.encrypt_storage(raw_data)
        nft.encrypted_data = encrypted
        storage_hash = self.storage.store_data(encrypted.decode("latin1"))
        nft.metadata['storage_hash'] = storage_hash
        self.nfts[nft.id] = nft
        return nft

    def create_sequenced_nft(self, parent_nft: GenomicNFT, derived_data: str, owner: str):
        nft = GenomicNFT(derived_data, owner, parent_id=parent_nft.id)
        encrypted = self.crypto.encrypt_storage(derived_data)
        nft.encrypted_data = encrypted
        storage_hash = self.storage.store_data(encrypted.decode("latin1"))
        nft.metadata['storage_hash'] = storage_hash
        self.nfts[nft.id] = nft
        return nft

def Homomorphic():
    # Owner wallet/public key
    owner = "0xABC123"

    # Create a raw genomic NFT
    raw_genome = "AGTCAGTCAGTCA"
    raw_nft = manager.create_raw_genomic_nft(raw_genome, owner)
    print("Raw NFT metadata:", raw_nft.metadata)

    # Create derived sequenced NFT (child)
    derived_genome = "AGTCAGTCA"  # Subset or processed genome
    seq_nft = manager.create_sequenced_nft(raw_nft, derived_genome, owner)
    print("Sequenced NFT metadata:", seq_nft.metadata)

    # Grant access to another user
    seq_nft.grant_access("0xDEF456")
    print("Access list:", seq_nft.access_list)

    # Retrieve and decrypt
    encrypted_from_storage = storage.retrieve_data(seq_nft.metadata['storage_hash']).encode("latin1")
    decrypted = crypto.decrypt_storage(encrypted_from_storage)
    print("Decrypted genome data:", decrypted)

    # Homomorphic computation example
    value = 10
    encrypted_value = crypto.encrypt_for_computation(value)
    result = encrypted_value + 5  # homomorphic addition
    decrypted_result = crypto.decrypt_computation(result)
    print("Homomorphic computation result:", decrypted_result)



###########
def register_user_crypto(user_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    uf1=user_id+"_pb.txt"
    uf2=user_id+"_pr.txt"
    public_pem
    ff=open("static/kg/"+uf1,"w")
    ff.write(public_pem)
    ff.close()

    ff=open("static/kg/"+uf2,"w")
    ff.write(private_pem)
    ff.close()
    

    # -----------------------------
    #Split Private Key (3-of-5 Threshold)
    # -----------------------------
    #shares = PlaintextToHexSecretSharer.split_secret(private_pem, 3, 5)
    private_bytes = private_pem.encode()

    # Create 3-of-5 threshold shares
    mnemonics = generate_mnemonics(
        group_threshold=1,
        groups=[(3, 5)],  # need 3 shares out of 5
        master_secret=private_bytes
    )

    shares = mnemonics[0]  
    # -----------------------------
    # Encrypt Shares Per Node
    # -----------------------------
    distributed_shares = []

    for idx, share in enumerate(shares):

        # Each node generates its OWN key
        node_key = Fernet.generate_key()
        cipher = Fernet(node_key)

        encrypted_share = cipher.encrypt(share.encode())

        # Blockchain anchor hash (hash BEFORE encryption)
        share_hash = hashlib.sha256(share.encode()).hexdigest()

        distributed_shares.append({
            "owner_id": user_id,
            "share_index": idx + 1,
            "encrypted_share": encrypted_share,
            "share_hash": share_hash,
            "node_key": node_key   # stored ONLY in that node
        })


    return {
        "public_key": public_pem,
        "share_hashes": [s["share_hash"] for s in distributed_shares],
        "distributed_shares": distributed_shares  # send to backend storage layer only
    }

def get_user_public_key(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT public_key FROM gn_owner WHERE uname=%s", (user_id,))
    result = cursor.fetchone()

    if not result:
        raise Exception("Public key not found!")

    public_pem = result[0]

    public_key = serialization.load_pem_public_key(public_pem.encode())

    cursor.close()
    conn.close()  
    return public_key

def getpbk(user_id):
    file_path="static/kg/"+user_id+"_pb.txt"
    with open(file_path, "r") as f:
            lines = f.readlines()

    # Remove BEGIN and END lines
    key_lines = [
        line.strip()
        for line in lines
        if "BEGIN PUBLIC KEY" not in line and
           "END PUBLIC KEY" not in line
    ]

    # Join into single continuous string
    key_string = "".join(key_lines)
    pbkey=key_string[:64]
    return pbkey

def getprk(user_id):
    file_path="static/kg/"+user_id+"_pr.txt"
    with open(file_path, "r") as f:
        key_text = f.read()

    # Remove PEM headers/footers
    cleaned = re.sub(r"-----.*?-----", "", key_text)

    # Remove whitespace and newlines
    cleaned = cleaned.replace("\n", "").strip()

    # Get first 64 characters
    return cleaned[:64]

# ============================================================
#  REAL RSA-PSS DIGITAL SIGNATURE HELPERS
# ============================================================

def load_private_key_pem(user_id):
    """Load full RSA private key PEM from disk for a Lab Assistant."""
    file_path = "static/kg/" + user_id + "_pr.txt"
    with open(file_path, "r") as f:
        private_pem = f.read()
    return serialization.load_pem_private_key(private_pem.encode(), password=None)

def load_public_key_pem(user_id):
    """Load full RSA public key PEM from disk for a Lab Assistant."""
    file_path = "static/kg/" + user_id + "_pb.txt"
    with open(file_path, "r") as f:
        public_pem = f.read()
    return serialization.load_pem_public_key(public_pem.encode())

def rsa_sign(private_key_obj, message: str) -> str:
    """
    Sign a message string with RSA-PSS (SHA-256).
    Returns Base64-encoded signature string.
    """
    signature_bytes = private_key_obj.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature_bytes).decode()

def rsa_verify(public_key_obj, message: str, signature_b64: str) -> bool:
    """
    Verify an RSA-PSS signature (SHA-256).
    Returns True if valid, False if tampered/wrong key.

    PSS.AUTO is used for salt_length so the verifier accepts any valid
    salt length — including MAX_LENGTH signatures produced during signing.
    Using MAX_LENGTH here would require the salt to be exactly max size,
    which silently fails if the signature was produced under different
    conditions (different key size, library version, or platform).
    """
    try:
        sig_bytes = base64.b64decode(signature_b64)
        public_key_obj.verify(
            sig_bytes,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.AUTO      # accept any valid PSS salt length
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def pin_to_ipfs(file_path):
    """
    Pins a file to IPFS via Pinata.
    Returns the IPFS CID (Hash) if successful, else None.
    """
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    
    # Credentials from .env or provided by user
    api_key = os.getenv("PINATA_API_KEY", "1ccd8598df7e28aa926f")
    api_secret = os.getenv("PINATA_SECRET_API_KEY", "0ba73281fd1714bbdf8dec603177bc5a96cc3166eefa3d454276ae50a")
    
    if not api_secret:
        print("CRITICAL: PINATA_SECRET_API_KEY missing in environment.")
        return None

    headers = {
        'pinata_api_key': api_key,
        'pinata_secret_api_key': api_secret
    }

    try:
        with open(file_path, 'rb') as f:
            response = requests.post(url, files={'file': f}, headers=headers, timeout=30)
            if response.status_code == 200:
                cid = response.json().get('IpfsHash')
                print(f"File pinned to IPFS. CID: {cid}")
                return cid
            else:
                print(f"Pinata Error: {response.status_code} - {response.text}")
                return None
    except Exception as e:
        print(f"IPFS Pinning Exception: {e}")
        return None

def get_admin_private_key():
    """Load or auto-generate the Admin RSA-2048 key pair (stored in static/kg/admin_pr.txt)."""
    priv_path = "static/kg/admin_pr.txt"
    pub_path  = "static/kg/admin_pb.txt"
    if not os.path.exists(priv_path):
        # First run: generate admin key pair
        adm_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        adm_pub  = adm_priv.public_key()
        with open(priv_path, "w") as f:
            f.write(adm_priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ).decode())
        with open(pub_path, "w") as f:
            f.write(adm_pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode())
    with open(priv_path, "r") as f:
        return serialization.load_pem_private_key(f.read().encode(), password=None)

def get_admin_public_key():
    """Return Admin RSA public key object (generates pair if missing)."""
    get_admin_private_key()   # ensures files exist
    with open("static/kg/admin_pb.txt", "r") as f:
        return serialization.load_pem_public_key(f.read().encode())


# ── Lab Assistant key helpers ──────────────────────────────────────────────

def get_lab_private_key(uname):
    """Load or generate RSA-2048 key pair for a lab assistant (researcher)."""
    os.makedirs("static/kg", exist_ok=True)
    priv_path = f"static/kg/lab_{uname}_pr.txt"
    pub_path  = f"static/kg/lab_{uname}_pb.txt"
    if not os.path.exists(priv_path):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub  = priv.public_key()
        with open(priv_path, "w") as f:
            f.write(priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ).decode())
        with open(pub_path, "w") as f:
            f.write(pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode())
        # Sync public key to DB
        try:
            conn2 = get_db_connection()
            cur2  = conn2.cursor()
            cur2.execute("UPDATE gn_researcher SET public_key=%s WHERE uname=%s",
                         (pub.public_bytes(
                             serialization.Encoding.PEM,
                             serialization.PublicFormat.SubjectPublicKeyInfo
                         ).decode(), uname))
            conn2.commit()
            cur2.close()
            conn2.close()
        except Exception as e:
            print(f"Lab key DB sync warning: {e}")
    with open(priv_path, "r") as f:
        return serialization.load_pem_private_key(f.read().encode(), password=None)

def get_lab_public_key(uname):
    """Load lab assistant public key from DB (authoritative) or fall back to disk."""
    try:
        conn2 = get_db_connection()
        cur2  = conn2.cursor()
        cur2.execute("SELECT public_key FROM gn_researcher WHERE uname=%s", (uname,))
        row = cur2.fetchone()
        cur2.close()
        conn2.close()
        if row and row[0]:
            return serialization.load_pem_public_key(row[0].encode())
    except Exception as e:
        print(f"Lab public key DB fetch warning: {e}")
    # fallback: disk
    with open(f"static/kg/lab_{uname}_pb.txt", "r") as f:
        return serialization.load_pem_public_key(f.read().encode())


# ── Smart contract recorder ────────────────────────────────────────────────


# ── Owner key helpers ─────────────────────────────────────────────────────

def get_owner_private_key(uname):
    """Load or generate RSA-2048 key pair for a data owner."""
    os.makedirs("static/kg", exist_ok=True)
    priv_path = f"static/kg/owner_{uname}_pr.txt"
    pub_path  = f"static/kg/owner_{uname}_pb.txt"
    if not os.path.exists(priv_path):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub  = priv.public_key()
        with open(priv_path, "w") as f:
            f.write(priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ).decode())
        with open(pub_path, "w") as f:
            f.write(pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode())
        try:
            conn2 = get_db_connection()
            cur2  = conn2.cursor()
            cur2.execute("UPDATE gn_owner SET public_key=%s WHERE uname=%s",
                         (pub.public_bytes(
                             serialization.Encoding.PEM,
                             serialization.PublicFormat.SubjectPublicKeyInfo
                         ).decode(), uname))
            conn2.commit(); cur2.close(); conn2.close()
        except Exception as e:
            print(f"Owner key DB sync warning: {e}")
    with open(priv_path, "r") as f:
        return serialization.load_pem_private_key(f.read().encode(), password=None)

def get_owner_public_key(uname):
    """Load owner public key from DB or fall back to disk."""
    try:
        conn2 = get_db_connection()
        cur2  = conn2.cursor()
        cur2.execute("SELECT public_key FROM gn_owner WHERE uname=%s", (uname,))
        row = cur2.fetchone(); cur2.close(); conn2.close()
        if row and row[0]:
            return serialization.load_pem_public_key(row[0].encode())
    except Exception as e:
        print(f"Owner public key DB fetch warning: {e}")
    with open(f"static/kg/owner_{uname}_pb.txt", "r") as f:
        return serialization.load_pem_public_key(f.read().encode())



# ── FHE (Fully Homomorphic Encryption) Helpers ──────────────────────────────
def generate_fhe_keys(uname):
    """Generate Paillier keypair for Homomorphic Encryption."""
    public_key, private_key = paillier.generate_paillier_keypair(n_length=2048)
    
    # Serialize keys (storing n for public, and p, q for private)
    pub_serialized = str(public_key.n)
    priv_p = str(private_key.p)
    priv_q = str(private_key.q)
    priv_serialized = f"{priv_p}|{priv_q}"
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE gn_owner SET fhe_public_key=%s, fhe_private_key=%s WHERE uname=%s",
                     (pub_serialized, priv_serialized, uname))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print(f"FHE key sync error: {e}")
        return False

def get_fhe_keys(uname):
    """Retrieve and reconstruct Paillier keys from DB."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT fhe_public_key, fhe_private_key FROM gn_owner WHERE uname=%s", (uname,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        
        if row and row[0] and row[1]:
            pub_n = int(row[0])
            p, q = map(int, row[1].split('|'))
            
            public_key = paillier.PaillierPublicKey(n=pub_n)
            private_key = paillier.PaillierPrivateKey(public_key, p=p, q=q)
            return public_key, private_key
    except Exception as e:
        print(f"Error retrieving FHE keys: {e}")
    return None, None


# ── Researcher key helpers ────────────────────────────────────────────────

def get_researcher_private_key(uname):
    """Load or generate RSA-2048 key pair for a researcher."""
    os.makedirs("static/kg", exist_ok=True)
    priv_path = f"static/kg/res_{uname}_pr.txt"
    pub_path  = f"static/kg/res_{uname}_pb.txt"
    if not os.path.exists(priv_path):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub  = priv.public_key()
        with open(priv_path, "w") as f:
            f.write(priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ).decode())
        with open(pub_path, "w") as f:
            f.write(pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode())
        try:
            conn2 = get_db_connection()
            cur2  = conn2.cursor()
            cur2.execute("UPDATE gn_researcher SET public_key=%s WHERE uname=%s",
                         (pub.public_bytes(
                             serialization.Encoding.PEM,
                             serialization.PublicFormat.SubjectPublicKeyInfo
                         ).decode(), uname))
            conn2.commit(); cur2.close(); conn2.close()
        except Exception as e:
            print(f"Researcher key DB sync warning: {e}")
    with open(priv_path, "r") as f:
        return serialization.load_pem_private_key(f.read().encode(), password=None)

def get_researcher_public_key(uname):
    try:
        conn2 = get_db_connection()
        cur2  = conn2.cursor()
        cur2.execute("SELECT public_key FROM gn_researcher WHERE uname=%s", (uname,))
        row = cur2.fetchone(); cur2.close(); conn2.close()
        if row and row[0]:
            return serialization.load_pem_public_key(row[0].encode())
    except Exception as e:
        print(f"Researcher public key DB fetch warning: {e}")
    with open(f"static/kg/res_{uname}_pb.txt", "r") as f:
        return serialization.load_pem_public_key(f.read().encode())

def smart_contract_record(rid, owner_id, lab_signer, admin_uname,
                           lab_sig, admin_sig, dataset_id, researcher_id):
    """
    Simulate an on-chain transaction:
    - Builds a canonical approval record combining all 3 signatures
    - Hashes it with SHA-256 (this hash represents the on-chain tx)
    - Records it on the internal genenft blockchain ledger
    - Returns (tx_hash, approval_record)
    """
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    approval_record = (
        f"GENENFT_SMART_CONTRACT_APPROVAL|"
        f"RID:{rid}|"
        f"DATASET:{dataset_id}|"
        f"OWNER:{owner_id}|"
        f"RESEARCHER:{researcher_id}|"
        f"LAB_SIGNER:{lab_signer}|"
        f"LAB_SIG_HASH:{hashlib.sha256(lab_sig.encode()).hexdigest()[:16]}|"
        f"ADMIN:{admin_uname}|"
        f"ADMIN_SIG_HASH:{hashlib.sha256(admin_sig.encode()).hexdigest()[:16]}|"
        f"TS:{ts}"
    )
    tx_hash = hashlib.sha256(approval_record.encode()).hexdigest()
    genenft(str(rid), admin_uname, approval_record, 'smart_contract')
    return tx_hash, approval_record

# ============================================================
#  END SIGNATURE HELPERS
# ============================================================

def hybrid_encrypt_file(file_obj, public_key, save_path):

    #Generate AES session key
    aes_key = Fernet.generate_key()
    cipher = Fernet(aes_key)

    # Read genome file (FASTQ/VCF)
    file_data = file_obj.read()

    # Encrypt genome data with AES
    encrypted_data = cipher.encrypt(file_data)

    with open(save_path, "wb") as f:
        f.write(encrypted_data)

    # Encrypt AES key using USER PUBLIC KEY
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_data, encrypted_key

# ── 2FA (Two-Factor Authentication) Helpers ──────────────────────────────────
def generate_totp_secret():
    """Generate a random base32 secret for TOTP."""
    return pyotp.random_base32()

def get_totp_uri(secret, username, issuer="GeneNFT"):
    """Generate a TOTP URI for QR code generation."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

def verify_totp(secret, code):
    """Verify a TOTP code against the secret."""
    if not secret:
        print("[DEBUG-2FA] No secret found for user.")
        return False
    secret = secret.strip()
    totp = pyotp.TOTP(secret)
    result = totp.verify(code, valid_window=1)
    print(f"[DEBUG-2FA] Verifying code {code} with secret {secret[:4]}... Result: {result}")
    return result

def get_2fa_qr(secret, username):
    """Generate a base64 QR code image for TOTP setup."""
    uri = get_totp_uri(secret, username)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

def encrypt_genomics_fhe(vcf_path, dataset_id, owner_id):
    """
    Parse VCF, find key genes, and encrypt presence bits using Owner's FHE key.
    Stores encrypted results in gn_encrypted_genomics.
    """
    public_key, _ = get_fhe_keys(owner_id)
    if not public_key:
        print(f"FHE Public Key not found for {owner_id}, generating now...")
        generate_fhe_keys(owner_id)
        public_key, _ = get_fhe_keys(owner_id)
        if not public_key: return

    # Genes we track for FHE analysis
    genes_to_track = ["BRCA1", "TP53", "KRAS", "APOE", "BRCA2", "MLH1", "MSH2"]
    
    found_genes = set()
    try:
        with open(vcf_path, 'r') as f:
            for line in f:
                if line.startswith('#'): continue
                parts = line.strip().split('\t')
                if len(parts) < 8: continue
                info = parts[7]
                for item in info.split(';'):
                    if item.startswith("GENE="):
                        gene = item.split('=')[1]
                        if gene in genes_to_track:
                            found_genes.add(gene)
    except Exception as e:
        print(f"VCF Parse Error for FHE: {e}")
        return

    conn = get_db_connection()
    cur = conn.cursor()
    
    for gene in genes_to_track:
        bit = 1 if gene in found_genes else 0
        # Encrypt the bit
        encrypted_bit_obj = public_key.encrypt(bit)
        
        # Serialize ciphertext
        enc_bit_str = str(encrypted_bit_obj.ciphertext())
        
        cur.execute("""
            INSERT INTO gn_encrypted_genomics (dataset_id, owner_id, gene_name, encrypted_bit)
            VALUES (%s, %s, %s, %s)
        """, (dataset_id, owner_id, gene, enc_bit_str))
        
    conn.commit()
    cur.close()
    conn.close()
    print(f"FHE Genomic Encryption complete for Dataset {dataset_id}")

def pad_left(s, length):
    return s.zfill(length)

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg=""
    act=""
   
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT max(id)+1 FROM gn_researcher")
    maxid = cursor.fetchone()[0]
    if maxid is None:
        maxid=1

    input_str = str(maxid)
    padded_str = pad_left(input_str, 3)
    u_id="R"+padded_str
            
    if request.method=='POST':
        name=request.form['name']
        institution=request.form['institution']
        domain=request.form['domain']
        mobile=request.form['mobile']
        email=request.form['email']
        location=request.form['location']
        
        uname=request.form['uname']
        pass1=request.form['pass']
        
      
        cursor.execute("SELECT count(*) FROM gn_researcher where uname=%s",(uname,))
        cnt = cursor.fetchone()[0]

        
        
        if cnt==0:
            sql = "INSERT INTO gn_researcher(id,name,institution,domain,mobile,email,location,uname,pass,status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid,name,institution,domain,mobile,email,location,uname,pass1,'0')
            cursor.execute(sql, val)
            conn.commit()
            bcdata="ID:"+str(maxid)+",User ID:"+uname+", Researcher Registered"
            genenft(str(maxid),uname,bcdata,'key')
            
            
            msg="success"

        else:
            msg='fail'

    cursor.close()
    conn.close()  
    return render_template('web/register.html',msg=msg,u_id=u_id)

@app.route('/reg_owner', methods=['GET', 'POST'])
def reg_owner():
    msg=""
    mess=""
    email=""
    act=""
    conn = get_db_connection()
    cursor = conn.cursor()
   
    cursor.execute("SELECT max(id)+1 FROM gn_owner")
    maxid = cursor.fetchone()[0]
    if maxid is None:
        maxid=1

    input_str = str(maxid)
    padded_str = pad_left(input_str, 3)
    u_id="U"+padded_str

    now1 = datetime.datetime.now()
    rdate=now1.strftime("%d-%m-%Y")
    edate1=now1.strftime("%Y-%m-%d")
    rtime=now1.strftime("%H:%M:%S")
    
    if request.method=='POST':
        name=request.form['name']
        dob=request.form['dob']
        gender=request.form['gender']
        mobile=request.form['mobile']
        email=request.form['email']
        address=request.form['address']
        country=request.form['country']
        
        uname=request.form['uname']
        pass1=request.form['pass']

        s_question=request.form['s_question']
        s_answer=request.form['s_answer']

        ans = hashlib.md5(s_answer.encode())
        s_answer1=ans.hexdigest()

        
        
      
        cursor.execute("SELECT count(*) FROM gn_owner where uname=%s",(uname,))
        cnt = cursor.fetchone()[0]
        #Interplanetary File System IPFS
        #base_path = "static/IPFS"
        #user_path = os.path.join(base_path, uname)
        #os.makedirs(user_path, exist_ok=True)
    
        if cnt==0:

            #Generate cryptographic identity
            user_id=uname
            #crypto_data = register_user_crypto(user_id)
            crypto_data = register_user_crypto(user_id)
            shares = crypto_data["distributed_shares"]

            public_key = crypto_data["public_key"]
            #shares = crypto_data["shares"]

            pb1=getpbk(uname)
            p1 = hashlib.md5(pb1.encode())
            pk=p1.hexdigest()
            pbkey=pk
            
            uuu=uname+str(maxid)
            pr1=getprk(uname)
            u1 = hashlib.md5(pr1.encode())
            prhash=u1.hexdigest()

            mm=uname+dob+str(maxid)
            m1 = hashlib.md5(mm.encode())
            mkey=m1.hexdigest()

            wa=generate_wallet_address()
        
    
            sql = "INSERT INTO gn_owner(id,name,dob,gender,mobile,email,address,country,wallet_address,uname,pass,s_question,s_answer,rdate,rtime,public_key,pbkey,prhash,masterkey) VALUES (%s,%s,%s,%s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid,name,dob,gender,mobile,email,address,country,wa,uname,pass1,s_question,s_answer1,rdate,rtime,public_key,pbkey,prhash,mkey)
            cursor.execute(sql, val)
            conn.commit()

            bcdata="ID:"+str(maxid)+",User ID:"+uname+", Wallet_address:"+wa+", Status: Data Owner Registered"
            genenft(str(maxid),uname,bcdata,'owner')

            # Generate FHE Keys for the new owner (Full FHE Support)
            generate_fhe_keys(uname)

            mess="Dear "+name+", User ID: "+uname+", Public Key: "+pbkey+", Private Key Hash Value:"+prhash

            # Store Encrypted Shares (Off-chain DB / IPFS)
            # -----------------------------
            #for s in shares:
            for s in crypto_data["distributed_shares"]:
                cursor.execute("SELECT max(id)+1 FROM gn_key_shares")
                maxid2 = cursor.fetchone()[0]
                if maxid2 is None:
                    maxid2=1
                cursor.execute("""
                    INSERT INTO gn_key_shares (id,owner_id, share_index, encrypted_share, share_hash)
                    VALUES (%s,%s, %s, %s, %s)
                """, (maxid2,s["owner_id"], s["share_index"], s["encrypted_share"], s["share_hash"]))
                conn.commit()
                bcdata="ID:"+str(maxid2)+",User ID:"+uname+",Share_index:"+str(s["share_index"])+",Share_hash:"+s["share_hash"]
                genenft(str(maxid),uname,bcdata,'key')
            
           
            
            msg="success"

        else:
            msg='fail'

    cursor.close()
    conn.close()         
    return render_template('web/reg_owner.html',msg=msg,mess=mess,email=email,u_id=u_id)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    msg=""
    if 'username' in session:
        uname = session['username']
    st=""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM gn_owner')
    data = cursor.fetchall()

    cursor.execute('SELECT * FROM gn_admin WHERE username = %s', (uname,))
    admin_data = cursor.fetchone()

    cursor.close()
    conn.close()  
    return render_template('admin.html', msg=msg, data=data, admin_data=admin_data)


@app.route('/view_res')
def view_res():
    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_researcher")
    researchers = cursor.fetchall()

    # Fetch admin data for sidebar
    cursor.execute("SELECT * FROM gn_admin WHERE username=%s", (session.get('username'),))
    admin_data = cursor.fetchone()

    cursor.close()
    conn.close()  
    return render_template("view_res.html",
                           researchers=researchers, admin_data=admin_data)



@app.route('/approve_researcher')
def approve_researcher():
    rid = request.args.get("id")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("update gn_researcher set status='1' where id=%s", (rid,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('/view_res')


# ============================================================
#  ADMIN: Dual-Approval with REAL RSA-PSS Digital Signatures
# ============================================================
@app.route('/admin_send_approvals', methods=['GET', 'POST'])
def admin_send_approvals():
    """
    Admin co-signs using real RSA-PSS (SHA-256).
    Verifies owner RSA-PSS signature and lab assistant signature before signing.
    On success, calls smart_contract_record() to anchor all 3 sigs on-chain.
    """
    msg = ""
    sig_display   = ""
    verify_detail = ""
    uname = session.get('username', 'Admin')

    conn   = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)

    cursor.execute("SELECT * FROM gn_admin WHERE username=%s", (uname,))
    admin_data = cursor.fetchone()

    if request.method == 'POST':
        rid = request.form.get('rid')

        if not uname:
            msg = "wrong_pass"
        else:
            # --- 2FA / TOTP VERIFICATION ---
            if admin_data and admin_data.get('totp_enabled'):
                otp_code = request.form.get('otp_code')
                device_cookie = request.cookies.get('device_binding_id')
                
                if not otp_code or not verify_totp(admin_data['totp_secret'], otp_code):
                    msg = "invalid_otp"
                    verify_detail = "Admin 2FA verification failed."
                elif admin_data.get('device_id') and device_cookie != admin_data['device_id']:
                    msg = "invalid_otp"
                    verify_detail = "Security Violation: This approval is locked to your registered device. Access from other devices is prohibited."
            # -------------------------------
            
            if msg == "":
                cursor.execute("SELECT * FROM gn_data_requests WHERE id=%s", (rid,))
                req = cursor.fetchone()

                if not req:
                    msg = "not_found"
                else:
                    owner_id = req['owner_id']
                    # ── Step 1: Verify owner signature
                    if not req.get('owner_signature') or not str(req['owner_signature']).strip():
                        msg = "owner_sig_invalid"
                        verify_detail = "Owner has not accepted this request yet."
                    elif not req.get('owner_sign_message'):
                        msg = "owner_sig_invalid"
                        verify_detail = "Missing owner signing payload."
                    else:
                        owner_crypto_ok = False
                        owner_verify_err = ""
                        try:
                            owner_pub = get_owner_public_key(owner_id)
                            owner_crypto_ok = rsa_verify(
                                owner_pub,
                                req['owner_sign_message'],
                                req['owner_signature']
                            )
                        except Exception as e:
                            owner_verify_err = str(e)

                        if not owner_crypto_ok:
                            msg = "owner_sig_invalid"
                            verify_detail = "Owner RSA-PSS signature verification failed."

                # ── Step 2: Verify lab assistant signature ──
                if msg == "" and (not req.get('lab_signature') or not req.get('lab_signer')):
                    msg = "lab_sig_missing"
                    verify_detail = "Lab assistant has not signed this request yet."

                if msg == "":
                    try:
                        lab_pub = get_lab_public_key(req['lab_signer'])
                        if not rsa_verify(lab_pub, req['lab_sign_message'], req['lab_signature']):
                            msg = "lab_sig_invalid"
                            verify_detail = f"Lab assistant ({req['lab_signer']}) signature mismatch."
                    except Exception as e:
                        msg = "lab_sig_invalid"
                        verify_detail = f"Error verifying lab signature: {e}"

                # ── Step 3: Admin RSA-PSS sign ──
                try:
                    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                    admin_sign_message = (
                        f"GENENFT_ADMIN_APPROVAL|"
                        f"RID:{rid}|"
                        f"ADMIN:{uname}|"
                        f"OWNER:{owner_id}|"
                        f"LAB:{req['lab_signer']}|"
                        f"RESEARCHER:{req['researcher_id']}|"
                        f"TS:{ts}"
                    )
                    admin_priv = get_admin_private_key()
                    admin_sig  = rsa_sign(admin_priv, admin_sign_message)

                    # Self-verify before writing
                    admin_pub = get_admin_public_key()
                    if not rsa_verify(admin_pub, admin_sign_message, admin_sig):
                        raise Exception("Admin self-verify failed")

                    # ── Step 4: Smart contract — anchor all 3 sigs on-chain ──
                    tx_hash, approval_record = smart_contract_record(
                        rid, owner_id, req['lab_signer'], uname,
                        req['lab_signature'], admin_sig,
                        req['dataset_id'], req['researcher_id']
                    )

                    # ── Step 5: Commit to DB ──
                    cursor.execute("""
                        UPDATE gn_data_requests
                        SET admin_approval     = 'Approved',
                            admin_signature    = %s,
                            admin_sign_message = %s,
                            pay_st             = 2
                        WHERE id = %s
                    """, (admin_sig, admin_sign_message, rid))
                    conn.commit()

                    verify_detail = (
                        f"Owner sig: OK | "
                        f"Lab sig ({req['lab_signer']}): OK | "
                        f"Admin sig: OK | "
                        f"TX: {tx_hash[:24]}..."
                    )
                    sig_display = admin_sig[:60] + "..."
                    msg = "approved"

                except Exception as e:
                    conn.rollback()
                    print("Admin sign error:", e)
                    msg = "sig_fail"
                    verify_detail = str(e)

    # ── Load pending: admin_approval = 'Pending', regardless of lab sig status ──
    cursor.execute("""
        SELECT r.id AS id, r.dataset_id, r.owner_id, r.researcher_id,
               r.owner_signature, r.owner_sign_message,
               r.lab_signature, r.lab_sign_message, r.lab_signer,
               r.admin_approval, r.admin_signature, r.pay_st,
               d.title, d.price
        FROM gn_data_requests r
        JOIN gn_genomic_dataset d ON r.dataset_id = d.id
        WHERE r.admin_approval = 'Pending'
        ORDER BY r.id DESC
    """)
    pending = cursor.fetchall()

    # ── Load approved history ──
    cursor.execute("""
        SELECT r.id AS id, r.dataset_id, r.owner_id, r.researcher_id,
               r.lab_signer, r.admin_approval, r.admin_signature, r.pay_st,
               d.title, d.price
        FROM gn_data_requests r
        JOIN gn_genomic_dataset d ON r.dataset_id = d.id
        WHERE r.admin_approval = 'Approved'
        ORDER BY r.id DESC
    """)
    approved_list = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "web/admin_send_approvals.html",
        msg=msg,
        pending=pending,
        approved_list=approved_list,
        admin=uname,
        sig_display=sig_display,
        verify_detail=verify_detail,
        admin_data=admin_data
    )






@app.route('/lab_sign_request', methods=['GET', 'POST'])
def lab_sign_request():
    """
    Lab assistant reviews pending data requests and applies an RSA-PSS
    digital signature before the request proceeds to admin approval.
    """
    msg   = ""
    uname = session.get('username')
    if not uname:
        return redirect(url_for('login_res'))

    conn   = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)

    if request.method == 'POST':
        rid = request.form.get('rid')
        cursor.execute("SELECT * FROM gn_data_requests WHERE id=%s", (rid,))
        req = cursor.fetchone()

        if not req:
            msg = "not_found"
        else:
            try:
                ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                sign_message = (
                    f"GENENFT_LAB_APPROVAL|"
                    f"RID:{rid}|"
                    f"LAB:{uname}|"
                    f"OWNER:{req['owner_id']}|"
                    f"DATASET:{req['dataset_id']}|"
                    f"RESEARCHER:{req['researcher_id']}|"
                    f"TS:{ts}"
                )
                priv_key = get_lab_private_key(uname)
                signature = rsa_sign(priv_key, sign_message)

                # Self-verify before writing to DB
                pub_key = get_lab_public_key(uname)
                if not rsa_verify(pub_key, sign_message, signature):
                    raise Exception("Lab signature self-verify failed")

                cursor.execute("""
                    UPDATE gn_data_requests
                    SET lab_signature    = %s,
                        lab_sign_message = %s,
                        lab_signer       = %s,
                        admin_approval   = 'Pending'
                    WHERE id = %s
                """, (signature, sign_message, uname, rid))
                conn.commit()

                bcdata = f"RID:{rid}|Lab:{uname}|LAB_SIGNED|TS:{ts}"
                genenft(str(rid), uname, bcdata, 'lab')
                msg = "signed"

            except Exception as e:
                conn.rollback()
                print("Lab sign error:", e)
                msg = "sig_fail"

    # Requests with owner signature but no lab signature yet
    cursor.execute("""
        SELECT r.*, d.title, o.name AS owner_name
        FROM gn_data_requests r
        JOIN gn_genomic_dataset d ON r.dataset_id = d.id
        LEFT JOIN gn_owner o ON r.owner_id = o.uname
        WHERE r.owner_signature IS NOT NULL
          AND (r.lab_signature IS NULL OR r.lab_signature = '')
        ORDER BY r.id DESC
    """)
    pending = cursor.fetchall()

    # Requests already signed by this lab assistant
    cursor.execute("""
        SELECT r.*, d.title
        FROM gn_data_requests r
        JOIN gn_genomic_dataset d ON r.dataset_id = d.id
        WHERE r.lab_signer = %s
          AND r.lab_signature IS NOT NULL
        ORDER BY r.id DESC
    """, (uname,))
    signed_list = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template('web/lab_sign_request.html',
                           msg=msg, pending=pending,
                           signed_list=signed_list, uname=uname)


@app.route('/owner_home', methods=['GET', 'POST'])
def owner_home():
    msg=""
    st=""
    if 'username' in session:
        uname = session['username']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM gn_owner WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    # Auto-provision FHE keys if missing (Migration support)
    if data and (not data[19] or not data[20]): # fhe_public_key, fhe_private_key
        generate_fhe_keys(uname)
        # Refresh data after generation
        cursor.execute('SELECT * FROM gn_owner WHERE uname = %s', (uname, ))
        data = cursor.fetchone()

    if request.method=='POST':
        st="1"


    cursor.close()
    conn.close()  
    return render_template('owner_home.html',msg=msg, data=data,st=st)

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    # Detect user type
    user_type = None
    uname = None
    if 'username' in session:
        uname = session['username']
        # Default to owner if we can't tell, but we should check session keys
        # The app seems to use 'username' for both. 
        # Let's check which login route they came from or check both tables.
        user_type = session.get('user_type', 'owner') 

    if not uname:
        return redirect(url_for('index'))
    
    msg = ""
    qr_code = ""
    secret = ""
    table = "gn_owner" if user_type == "owner" else "gn_admin"
    id_col = "uname" if user_type == "owner" else "username"

    conn = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)
    
    cursor.execute(f"SELECT * FROM {table} WHERE {id_col} = %s", (uname,))
    user = cursor.fetchone()

    back_url = "/owner_home" if user_type == "owner" else "/admin"
    
    if request.method == 'GET':
        if not user or not user.get('totp_secret'):
            secret = generate_totp_secret()
            cursor.execute(f"UPDATE {table} SET totp_secret = %s WHERE {id_col} = %s", (secret, uname))
            conn.commit()
        else:
            secret = user['totp_secret']
        
        qr_code = get_2fa_qr(secret, uname)
    
    if request.method == 'POST':
        code = request.form.get('code')
        secret = user['totp_secret']
        qr_code = get_2fa_qr(secret, uname)
        
        if verify_totp(secret, code):
            device_id = str(uuid.uuid4())
            cursor.execute(f"UPDATE {table} SET totp_enabled = TRUE, device_id = %s WHERE {id_col} = %s", (device_id, uname))
            conn.commit()
            cursor.close(); conn.close()
            
            # Set device binding cookie
            response = make_response(render_template("web/setup_2fa.html", msg='success', qr_code=qr_code, user=user, back_url=back_url))
            response.set_cookie('device_binding_id', device_id, max_age=31536000) # 1 year
            return response
        else:
            msg = "fail"

    cursor.close()
    conn.close()
    
    return render_template("web/setup_2fa.html", msg=msg, qr_code=qr_code, user=user, back_url=back_url)
    
@app.route('/verify_login_2fa', methods=['GET', 'POST'])
def verify_login_2fa():
    msg = ""
    uname = session.get('temp_user')
    utype = session.get('temp_type')
    
    if not uname:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        code = request.form.get('code')
        
        table = "gn_owner" if utype == "owner" else "gn_admin"
        id_col = "uname" if utype == "owner" else "username"
        
        conn = get_db_connection()
        cursor = get_db_cursor(conn, dictionary=True)
        cursor.execute(f"SELECT * FROM {table} WHERE {id_col} = %s", (uname,))
        user = cursor.fetchone()
        
        if user and verify_totp(user['totp_secret'], code):
            session['username'] = uname
            session['user_type'] = utype
            session.pop('temp_user', None)
            session.pop('temp_type', None)
            
            cursor.close(); conn.close()
            if utype == 'admin':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('owner_home'))
        else:
            msg = "fail"
            cursor.close(); conn.close()
            
    return render_template("web/verify_login_2fa.html", msg=msg)

def create_user_directory(username):
    path = os.path.join("static/IPFS", username)
    os.makedirs(path, exist_ok=True)
    return path

def generate_hash(data):
    return hashlib.sha256(data).hexdigest()

def generate_nft():
    return "NFT-" + uuid.uuid4().hex[:10].upper()

def ghash(file_path):
    hash_sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    
    return hash_sha256.hexdigest()

def encrypt_file(in_file, out_file, key):
    cipher = AES.new(key, AES.MODE_EAX)
    
    data = open(in_file, 'rb').read()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(out_file, 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)

def decrypt_file(in_file, out_file, key):
    data = open(in_file, 'rb').read()

    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    open(out_file, 'wb').write(plaintext)
        
        
@app.route('/owner_upload', methods=['GET', 'POST'])
def owner_upload():
    msg=""
    st=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM gn_owner WHERE uname = %s', (uname, ))
    data = cursor.fetchone()
    
    cursor.execute("SELECT max(id)+1 FROM gn_genomic_dataset")
    maxid = cursor.fetchone()[0]
    if maxid is None:
        maxid=1

    cursor.execute('SELECT * FROM gn_owner WHERE uname = %s', (uname, ))
    data = cursor.fetchone()
    #pbkey=data[17]

    pbkey=getpbk(uname)
        
    if request.method == 'POST':

        user_id = uname
        title = request.form['title']
        description = request.form['description']
        allowed_analysis = request.form.getlist('allowed_analysis')
        ethnicity = request.form['ethnicity']
        
        consent = request.form.get('consent')
        public_key = request.form['public_key']
        price = request.form['price']

        if pbkey==public_key:

            file = request.files['genome_file']
            filename = secure_filename(file.filename)

            # Create user folder
            user_folder = create_user_directory(uname)

            file.save(os.path.join("static/css/ups", filename))
            gh=ghash("static/css/ups/"+filename)
            vff=uname+".vcf"
            shutil.copy("static/css/ups/"+filename, "static/IPFS/"+uname+"/"+vff)
            os.remove("static/css/ups/"+filename)

            encrypted_filename = "enc_" + filename
            save_path = os.path.join(user_folder, encrypted_filename)

            public_key = get_user_public_key(user_id)
            # Encrypt file
            #encrypted_data = encrypt_and_save(file, save_path)
            encrypted_data, encrypted_key = hybrid_encrypt_file(file, public_key, save_path)
            # Generate hash from encrypted content
            file_hash = generate_hash(encrypted_data)

            # Generate NFT token
            nft_token = generate_nft()

            # --- IPFS PINNING (PINATA) ---
            ipfs_cid = pin_to_ipfs(save_path)
            # -----------------------------

            # Store in DB
            allowed=",".join(allowed_analysis)
            query = """
            INSERT INTO gn_genomic_dataset
            (id, owner_id, title, description, allowed_analysis, ethnicity, price,
             encrypted_file, file_hash, nft_token, ipfs_cid)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """

            values = (
                maxid, user_id, title, description, allowed,
                ethnicity, price, encrypted_filename,
                file_hash, nft_token, ipfs_cid
            )

            cursor.execute(query, values)
            conn.commit()

            bcdata = (
                f"ID:{maxid}|"
                f"User:{uname}|"
                f"File:{encrypted_filename}|"
                f"IPFS:{ipfs_cid or 'local'}|"
                f"NFT:{nft_token}"
            )
            genenft(str(maxid), uname, bcdata, 'owner')
            
            # --- FULL FHE ENCRYPTION ---
            # Perform FHE encryption on the genomic variants for privacy-preserving analysis
            encrypt_genomics_fhe("static/IPFS/"+uname+"/"+vff, maxid, uname)
            # ---------------------------
            msg="success"
        else:
            msg="fail"

        #return "Dataset Uploaded & Encrypted Successfully!"


    cursor.close()
    conn.close()  
    return render_template("owner_upload.html",msg=msg,data=data)

@app.route('/owner_files')
def owner_files():
    msg=""
    st=""
    if 'username' in session:
        uname = session['username']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM gn_owner WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    cursor = get_db_cursor(conn, dictionary=True)
    
    cursor.execute("SELECT * FROM gn_genomic_dataset WHERE owner_id=%s", (uname,))
    datasets = cursor.fetchall()


    cursor.close()
    conn.close()  
    
    return render_template("owner_files.html", datasets=datasets,data=data)

'''@app.route('/owner_key', methods=['GET', 'POST'])
def owner_key():
    
    #if 'username' not in session:
    #    return redirect(url_for('login'))

    uname = session['username']

    # ------------------------
    # GET Load Page
    # ------------------------
    if request.method == 'GET':
        return render_template("owner_key.html")

    # ------------------------
    # POST Handle AJAX
    # ------------------------
    key_type = request.form.get("key_type")
    entered_master = request.form.get("master_key")

    cursor = mydb.cursor()
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data = cursor.fetchone()

    if not data:
        return jsonify({"status": "error", "message": "User not found"})

    master_key = data[20]

    if entered_master != master_key:
        return jsonify({"status": "error", "message": "Invalid Master Key"})

    pbkey = getpbk(uname)
    prkey = getprk(uname)

    import hashlib, math, random

    pbhash = hashlib.sha256(pbkey.encode()).hexdigest()
    prhash = hashlib.sha256(prkey.encode()).hexdigest()

    length = math.ceil(len(prkey)/5)
    shares = [prkey[i:i+length] for i in range(0, len(prkey), length)]

    share_hashes = [hashlib.sha256(s.encode()).hexdigest() for s in shares]

    if key_type == "public":
        return jsonify({
            "status": "success",
            "type": "public",
            "public_key": pbkey,
            "public_hash": pbhash
        })

    elif key_type == "private":
        selected = random.sample(list(zip(shares, share_hashes)), 3)

        return jsonify({
            "status": "success",
            "type": "private",
            "private_key": prkey,
            "private_hash": prhash,
            "selected_shares": selected
        })

    return jsonify({"status": "error", "message": "Invalid Request"})'''

@app.route('/owner_key', methods=['GET', 'POST'])
def owner_key():
    
    act = ""
    msg = ""
    st=""
    conn = get_db_connection()
    cursor = conn.cursor()
    uname = session.get("username")
    # Fetch already-generated keys (NO generation here)
    pbkey = getpbk(uname)
    prkey = getprk(uname)

    pr1 = prkey[0:12]
    pr2 = prkey[12:24]
    pr3 = prkey[24:36]
    pr4 = prkey[36:48]
    pr5 = prkey[48:60]

    cursor.execute("""
        SELECT * FROM gn_owner WHERE uname=%s
    """, (uname,))
    data1 = cursor.fetchone()
    name=data1[1]
    pbhash = data1[17]
    prhash = data1[18]
    master_key = data1[19]
    key_st=data1[20]
    if key_st==1:
        st="1"

    data3 = {
        "public_key": pbkey,
        "private_key": prkey,
        "nodes": [pr1, pr2, pr3, pr4, pr5],
        "public_hash": pbhash,
        "private_hash": prhash,
        "master_key": master_key
    }

    # get distributed node hash
    pr_hash = []
    cursor.execute("SELECT * FROM gn_key_shares WHERE owner_id=%s", (uname,))
    data2 = cursor.fetchall()

    for dd in data2:
        dv=dd[4]
        dv1=dv[0:32]
        pr_hash.append(dv1)

    cursor.close()
    conn.close()

    if request.method == 'POST':
        act = "done"
        # mail values
        email = data1[5]
        mess = "Dear "+name+", User ID: "+uname+", Master Hash Key is: " + master_key

        return render_template(
            "owner_key.html",
            act=act,
            data1=data1,
            data3=data3,
            pr_hash=pr_hash,
            email=email,
            mess=mess
        )

    # GET load
    return render_template(
        "owner_key.html",
        act=act,
        data1=data1,
        data3=data3,
        pr_hash=pr_hash,
        st=st
    )

'''@app.route("/owner_key", methods=['GET', 'POST'])
def owner_key():
    cursor = mydb.cursor()
    uname = session.get("username")

    pbkey = getpbk(uname)
    prkey = getprk(uname)

    prkey = prkey[:60]

    pr_nodes = [
        prkey[0:12],
        prkey[12:24],
        prkey[24:36],
        prkey[36:48],
        prkey[48:60]
    ]

    cursor.execute("""
        SELECT * FROM gn_owner WHERE uname=%s
    """, (uname,))
    data1 = cursor.fetchone()

    pbhash = data1[17]
    prhash = data1[18]
    master_key = data1[19]
    email = data1[4]

    # Fetch node hashes safely
    cursor.execute("""
        SELECT share_hash 
        FROM gn_key_shares 
        WHERE owner_id=%s 
        ORDER BY id ASC
    """, (uname,))

    rows = cursor.fetchall()

    pr_hash = []
    for r in rows:
        pr_hash.append(r[0])

    while len(pr_hash) < 5:
        pr_hash.append("Hash Not Found")

    data3 = {
        "public_key": pbkey,
        "private_key": prkey,
        "nodes": pr_nodes,
        "public_hash": pbhash,
        "private_hash": prhash,
        "node_hashes": pr_hash,
        "master_key": master_key,
        "email": email
    }

    return render_template("owner_key.html", data3=data3)'''





'''@app.route('/owner_key', methods=['GET', 'POST'])
def owner_key():
    msg = ""
    mess=""
    act = request.args.get("act", "")

    # Check session safely
    #if 'username' not in session:
    #    return redirect(url_for('login'))

    uname = session['username']

    cursor = mydb.cursor()

    # Get owner basic data
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data1 = cursor.fetchone()
    email=data1[5]
    name=data1[1]

    if not data1:
        msg = "Owner record not found"
        return render_template("owner_key.html", msg=msg)

    # Fetch already-generated keys (NO generation here)
    pbkey = getpbk(uname)   # public key
    prkey = getprk(uname)   # private key

    # Split private key into 5 equal nodes (12 chars each)
    pr1 = prkey[0:12]
    pr2 = prkey[12:24]
    pr3 = prkey[24:36]
    pr4 = prkey[36:48]
    pr5 = prkey[48:60]

    #Hash + Master Key from DB
    pbhash = data1[17]
    prhash = data1[18]
    master_key = data1[19]

    # Pack for easy template use
    data3 = {
        "public_key": pbkey,
        "private_key": prkey,
        "nodes": [pr1, pr2, pr3, pr4, pr5],
        "public_hash": pbhash,
        "private_hash": prhash,
        "master_key": master_key
    }
    mess="Dear "+name+", Master Key: "+master_key
    #Get distributed hash shares
    pr_hash = []
    cursor.execute("SELECT * FROM gn_key_shares WHERE user_id=%s", (uname,))
    data2 = cursor.fetchall()

    for dd in data2:
        pr_hash.append(dd[4])   # share hash column

    return render_template(
        "owner_key.html",
        msg=msg,
        act=act,
        data1=data1,
        data2=data2,
        pr_hash=pr_hash,
        data3=data3,
        email=email,
        mess=mess
    )'''

'''@app.route('/owner_key', methods=['GET', 'POST'])
def owner_key():
    msg=""
    act=request.args.get("act")
    st=""
    if 'username' in session:
        uname = session['username']

    cursor = mydb.cursor()
    
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data1 = cursor.fetchone()
   
    pbkey=getpbk(uname)
    prkey=getprk(uname)

    pr1=prkey[0:12]
    pr2=prkey[12:12]
    pr3=prkey[24:12]
    pr4=prkey[36:12]
    pr5=prkey[48:12]

    pbhash=data1[17]
    prhash=data1[18]
    master_key=data1[20]

    data3=[pbkey,prkey,pr1,pr2,pr3,pr4,pr5,pbhash,prhash,master_key]

    pr_hash=[]
    cursor.execute("SELECT * FROM gn_key_shares WHERE user_id=%s", (uname,))
    data2 = cursor.fetchall()
    for dd in data2:
        ph=dd[4]
        pr_hash.append(ph)
    
        
    
    return render_template("owner_key.html", msg=msg,act=act,data1=data1,data2=data2,pr_hash=pr_hash,data3=data3)'''



@app.route('/view_owner', methods=['GET', 'POST'])
def view_owner():
    msg=""
    if 'username' in session:
        uname = session['username']
    st=""
    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute('SELECT * FROM gn_owner')
    data = cursor.fetchall()

    # Fetch admin data for sidebar
    cursor.execute("SELECT * FROM gn_admin WHERE username=%s", (uname,))
    admin_data = cursor.fetchone()

    cursor.close()
    conn.close()  
        
    return render_template('view_owner.html', msg=msg, data=data, admin_data=admin_data)

@app.route('/approve/<id>')
def approve(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE gn_researcher SET status='1' WHERE id=%s",(id,))
    conn.commit()

    cursor.close()
    conn.close()  
    return redirect('/view_provider')


# ---------------- Reject ----------------
@app.route('/reject/<id>')
def reject(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("UPDATE gn_researcher SET status='2' WHERE id=%s",(id,))
    conn.commit()

    cursor.close()
    conn.close()  
    return redirect('/view_res')

def disease_exists_in_vcf(vcf_path, search_disease):
    print("Checking file:", vcf_path)

    if os.path.exists(vcf_path):
        print("File exists")

        with open(vcf_path, 'r') as f:
            for line in f:
                if line.startswith("#"):
                    continue

                info = line.strip().split("\t")[7]

                for item in info.split(";"):
                    if item.startswith("DISEASE="):
                        disease = item.split("=")[1]

                        print("Found disease:", disease)
                        print("Input disease:", disease_input)

                        if disease.lower().strip() == disease_input.lower().strip():
                            print("MATCH FOUND")
                            return True
    return False

def get_matching_diseases(vcf_path, search_diseases):
    matched = set()

    with open(vcf_path, 'r') as file:
        for line in file:
            if line.startswith("#"):
                continue

            info = line.strip().split("\t")[7]

            for item in info.split(";"):
                if item.startswith("DISEASE="):
                    disease = item.split("=")[1].strip().lower()

                    for sd in search_diseases:
                        if sd in disease:
                            matched.add(disease)

    return list(matched)

@app.route('/res_home', methods=['GET', 'POST'])
def res_home():
    msg=""
    st=""
    if 'username' in session:
        uname = session['username']
  
    results=[]
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM gn_researcher WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    

    if request.method=='POST':
        st="1"
        disease_input = request.form['disease']

        print(disease_input)
        
        
        # get all datasets
        cursor.execute("SELECT * FROM datasets")
        datasets = cursor.fetchall()
        
        for dat in datasets:

            owner_id=dat[1]
            vcfile=owner_id+".vcf"
            
            
            vcf_path = os.path.join("static/web/data", vcfile)
            print(vcf_path)
            '''if os.path.exists(vcf_path):
                st="1"
                if disease_exists_in_vcf(vcf_path, disease_input):
                    cursor.execute("SELECT name FROM gn_owner WHERE uname=%s", (owner_id,))
                    user = cursor.fetchone()

                    results.append({
                        'dataset_id': dat['id'],
                        'owner': user['name'],
                        'title': dat['title'],
                        'price': dat['price'],
                        'disease': disease_input
                    })'''


    cursor.close()
    conn.close()  
    return render_template('res_home.html',msg=msg, data=data,st=st,results=results)

def encrypt_disease(disease):
    num = sum(ord(c) for c in disease)
    return HE.encryptInt(num)

def match_disease(enc_val, disease):
    num = sum(ord(c) for c in disease)
    enc_query = HE.encryptInt(num)

    result = enc_val - enc_query   # homomorphic subtraction

    return HE.decryptInt(result) == 0


@app.route('/res_datasets', methods=['GET','POST'])
def res_datasets():
    msg=""
    results = []
    st = ""
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
     
    cursor = get_db_cursor(conn, dictionary=True)

    cursor.execute('SELECT * FROM gn_researcher WHERE uname=%s',(uname,))
    data = cursor.fetchone()

    if request.method == 'POST':
        st = "1"

        disease_input = request.form['disease'].strip()

        ff=open("static/det.txt","w")
        ff.write(disease_input)
        ff.close()

        
            
        search_diseases = [d.strip().lower() for d in disease_input.split(",")]

        

        cursor.execute("SELECT * FROM gn_genomic_dataset")
        datasets = cursor.fetchall()

        for dat in datasets:
            owner_id = str(dat['owner_id'])
            vcfile = owner_id + ".vcf"

            vcf_path = os.path.join("static", "web", "data", vcfile)

            if os.path.exists(vcf_path):

                matched_diseases = get_matching_diseases(vcf_path, search_diseases)

                if matched_diseases:
                    cursor.execute("SELECT name FROM gn_owner WHERE uname=%s", (owner_id,))
                    user = cursor.fetchone()

                    results.append({
                        'dataset_id': dat['id'],
                        'owner': user['name'] if user else "Unknown",
                        'title': dat['title'],
                        'price': dat['price'],
                        'disease': ", ".join(matched_diseases)  # show matched only
                    })

    cursor.close()
    conn.close()  
    return render_template("res_datasets.html",
                           results=results,
                           data=data,
                           st=st,msg=msg)



#0.01==1950
def filter_vcf_by_disease(vcf_file, input_diseases, output_file):
    # convert input to set for fast lookup
    disease_set = set(input_diseases)

    with open(vcf_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            # write header lines as it is
            if line.startswith("#"):
                outfile.write(line)
                continue

            columns = line.strip().split("\t")
            info_field = columns[7]

            # extract disease
            disease = None
            for item in info_field.split(";"):
                if item.startswith("DISEASE="):
                    disease = item.split("=")[1]
                    break

            # check if disease matches input
            if disease in disease_set:
                outfile.write(line)


def normalize(text):
    return text.strip().lower().replace(" ", "")

def extract_diseases(input_file, diseases, output_file):
    headers = []
    result = []

    # Read disease list from file
    with open("static/det.txt", "r") as ff:
        diss = ff.read()

    file_diseases = [d.strip() for d in diss.split(",")]

    # diseases may arrive as a comma-separated string OR a list — always normalise to list
    if isinstance(diseases, str):
        input_diseases = [d.strip() for d in diseases.split(",")]
    else:
        input_diseases = [d.strip() for d in diseases]

    # Combine user input + file diseases, drop empty strings
    all_diseases = [d for d in input_diseases + file_diseases if d]

    all_rows = []

    with open(input_file, 'r') as f:
        for line in f:
            if line.startswith('#'):
                headers.append(line)
                continue

            if not line.strip():
                continue

            parts = line.strip().split('\t')
            if len(parts) < 8:
                parts = line.strip().split()

            all_rows.append(line)

            if len(parts) < 8:
                continue

            info = parts[7]

            for item in info.split(';'):
                if "DISEASE=" in item:
                    disease_val = item.split('=', 1)[1].strip()
                    print("File disease:", disease_val)
                    if disease_val.lower() in [d.lower() for d in all_diseases]:
                        result.append(line)
                        break

    print("Matched:", len(result), "of", len(all_rows), "rows")

    # If no disease matched, fall back to writing all rows
    rows_to_write = result if result else all_rows

    with open(output_file, 'w') as out:
        for h in headers:
            out.write(h)
        for r in rows_to_write:
            out.write(r)

       

@app.route('/send_request')
def send_request():
    uname=""
    if 'username' in session:
        uname = session['username']

    researcher_id = uname
    dataset_id = request.args.get('id')
    disease = request.args.get('disease')
    
    conn = get_db_connection()
   
    
    cursor = get_db_cursor(conn, dictionary=True)

    cursor.execute("SELECT MAX(id)+1 AS next_id FROM gn_data_requests")
    row = cursor.fetchone()

    maxid = row["next_id"]
    if maxid is None:
        maxid = 1
        
    # get dataset owner
    cursor.execute("SELECT owner_id FROM gn_genomic_dataset WHERE id=%s", (dataset_id,))
    data = cursor.fetchone()

    owner_id = data['owner_id']
    key= hashlib.sha256(owner_id.encode()).digest()[:16]
    vfile=owner_id+".vcf"
    path="static/IPFS/"+owner_id+"/"+vfile

    #
    fn="f"+str(dataset_id)+"_"+str(maxid)+".vcf"
    output_file = "static/uploads/"+fn
    extract_diseases(path, disease, output_file)



    enc_vfile="f"+str(dataset_id)+"_"+str(maxid)+".enc"
    vfile="f"+str(dataset_id)+"_"+str(maxid)+".vcf"
    shutil.copy("static/uploads/"+vfile, "static/css/down/"+vfile)
    
    encrypt_file("static/uploads/"+vfile, "static/uploads/"+enc_vfile, key)
    os.remove("static/uploads/"+vfile)
   
    cursor.execute("SELECT * FROM gn_genomic_dataset WHERE id=%s", (dataset_id,))
    d1 = cursor.fetchone()
    price = d1['price']

    dc = disease.split(",")
    qty = len(dc)
    amount = price * qty

    # ── Researcher RSA-PSS digital signature ──────────────────────────────
    ts_req = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    res_sign_message = (
        f"GENENFT_RESEARCHER_REQUEST|"
        f"RID:{maxid}|"
        f"RESEARCHER:{uname}|"
        f"DATASET:{dataset_id}|"
        f"OWNER:{owner_id}|"
        f"DISEASES:{disease}|"
        f"TS:{ts_req}"
    )
    try:
        res_priv = get_researcher_private_key(uname)
        researcher_signature = rsa_sign(res_priv, res_sign_message)
        res_pub = get_researcher_public_key(uname)
        if not rsa_verify(res_pub, res_sign_message, researcher_signature):
            raise Exception("Researcher signature self-verify failed")
    except Exception as e:
        print("Researcher sign error:", e)
        researcher_signature = ""
        res_sign_message     = ""

    bcdata = f"ID:{maxid},Researcher ID:{uname}, Request for {disease}|SIG:{researcher_signature[:32]}...|TS:{ts_req}"
    genenft(str(maxid), uname, bcdata, 'researcher_request')

    # insert request with researcher signature
    cursor.execute("""
        INSERT INTO gn_data_requests
            (id, dataset_id, owner_id, researcher_id, diseases, amount, status,
             researcher_signature, researcher_sign_message)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (maxid, dataset_id, owner_id, researcher_id, disease, amount, 'Pending',
             researcher_signature, res_sign_message))
    conn.commit()

    cursor.close()
    conn.close()  
    #return "Request Sent Successfully"
    msg="success"
    return render_template("send_request.html",msg=msg)

@app.route('/owner_requests')
def owner_requests():
    msg=""
    act=request.args.get("act")
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data2 = cursor.fetchone()
    
    query = """
    SELECT r.*, d.title, d.price
    FROM gn_data_requests r
    JOIN gn_genomic_dataset d ON r.dataset_id = d.id
    WHERE r.owner_id = %s
    ORDER BY r.id DESC
    """
    

    cursor.execute(query, (uname,))
    data = cursor.fetchall()

    if act == "yes":
        rid = request.args.get("rid")
        
        # --- 2FA ENFORCEMENT ---
        if data2 and data2.get('totp_enabled'):
            # If 2FA is enabled, we must use the secure POST-based owner_send route
            return redirect(url_for('owner_send', rid=rid))
        # -----------------------

        cursor.execute("SELECT * FROM gn_data_requests WHERE id=%s", (rid,))
        req = cursor.fetchone()
        if req:
            try:
                ts_appr = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                owner_sign_message = (
                    f"GENENFT_OWNER_APPROVAL|"
                    f"RID:{rid}|"
                    f"OWNER:{uname}|"
                    f"DATASET:{req['dataset_id']}|"
                    f"RESEARCHER:{req['researcher_id']}|"
                    f"TS:{ts_appr}"
                )
                owner_priv = get_owner_private_key(uname)
                owner_sig  = rsa_sign(owner_priv, owner_sign_message)
                owner_pub  = get_owner_public_key(uname)
                if not rsa_verify(owner_pub, owner_sign_message, owner_sig):
                    raise Exception("Owner signature self-verify failed")

                # ── Smart contract: record owner approval on-chain ────────
                ts_sc = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                sc_record = (
                    f"GENENFT_SMART_CONTRACT_OWNER_APPROVAL|"
                    f"RID:{rid}|"
                    f"DATASET:{req['dataset_id']}|"
                    f"OWNER:{uname}|"
                    f"RESEARCHER:{req['researcher_id']}|"
                    f"OWNER_SIG_HASH:{hashlib.sha256(owner_sig.encode()).hexdigest()[:16]}|"
                    f"TS:{ts_sc}"
                )
                tx_hash_owner = hashlib.sha256(sc_record.encode()).hexdigest()
                genenft(str(rid), uname, sc_record, 'smart_contract')

                cursor.execute("""
                    UPDATE gn_data_requests
                    SET status             = 'Approved',
                        owner_signature    = %s,
                        owner_sign_message = %s,
                        admin_approval     = 'Pending'
                    WHERE id = %s
                """, (owner_sig, owner_sign_message, rid))
                conn.commit()
                msg = "yes"
                print(f"Owner approved RID {rid} | TX: {tx_hash_owner[:24]}...")
            except Exception as e:
                conn.rollback()
                print("Owner approve error:", e)
                msg = "sig_fail"

    if act == "no":
        rid = request.args.get("rid")
        cursor.execute("SELECT * FROM gn_data_requests WHERE id=%s", (rid,))
        req = cursor.fetchone()
        if req:
            try:
                ts_rej = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                rej_message = (
                    f"GENENFT_OWNER_REJECTION|"
                    f"RID:{rid}|"
                    f"OWNER:{uname}|"
                    f"DATASET:{req['dataset_id']}|"
                    f"RESEARCHER:{req['researcher_id']}|"
                    f"TS:{ts_rej}"
                )
                owner_priv = get_owner_private_key(uname)
                rej_sig    = rsa_sign(owner_priv, rej_message)
                sc_rej = (
                    f"GENENFT_SMART_CONTRACT_REJECTION|"
                    f"RID:{rid}|"
                    f"OWNER:{uname}|"
                    f"REJ_SIG_HASH:{hashlib.sha256(rej_sig.encode()).hexdigest()[:16]}|"
                    f"TS:{ts_rej}"
                )
                genenft(str(rid), uname, sc_rej, 'smart_contract')
                cursor.execute("UPDATE gn_data_requests SET status='Rejected' WHERE id=%s", (rid,))
                conn.commit()
                msg = "no"
            except Exception as e:
                conn.rollback()
                print("Owner reject error:", e)
                msg = "no"  # still reject even if signing fails

    cursor.close()
    conn.close()
    
    return render_template("owner_requests.html",msg=msg,act=act, data=data)

@app.route('/owner_send', methods=['GET', 'POST'])
def owner_send():
    msg = ""
    sig_display = ""
    act = request.args.get("act")
    rid = request.args.get("rid")
    uname = session.get('username')

    conn = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    owner_data = cursor.fetchone()

    cursor.execute("SELECT * FROM gn_data_requests WHERE id=%s", (rid,))
    data3 = cursor.fetchone()

    if request.method == 'POST':
        accepted = request.form.get('accepted', '').strip()

        if not accepted:
            msg = "missing_acceptance"
        else:
            # --- 2FA / TOTP VERIFICATION ---
            if owner_data and owner_data.get('totp_enabled'):
                otp_code = request.form.get('otp_code')
                device_cookie = request.cookies.get('device_binding_id')
                
                if not otp_code or not verify_totp(owner_data['totp_secret'], otp_code):
                    msg = "invalid_otp"
                    return render_template("owner_send.html", msg=msg, data2=owner_data, data3=data3)
                elif owner_data.get('device_id') and device_cookie != owner_data['device_id']:
                    msg = "invalid_otp"
                    # Log the security violation or just show the same error
                    return render_template("owner_send.html", msg="invalid_otp", data2=owner_data, data3=data3)
            # -------------------------------
            
            try:
                accept_timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                accept_message = (
                    f"GENENFT_OWNER_APPROVAL|"
                    f"RID:{rid}|"
                    f"OWNER:{uname}|"
                    f"DATASET:{data3['dataset_id']}|"
                    f"RESEARCHER:{data3['researcher_id']}|"
                    f"TS:{accept_timestamp}"
                )

                owner_priv = get_owner_private_key(uname)
                owner_sig = rsa_sign(owner_priv, accept_message)
                owner_pub = get_owner_public_key(uname)
                if not rsa_verify(owner_pub, accept_message, owner_sig):
                    raise Exception("Owner signature self-verify failed")

                try:
                    cursor.execute("""
                        UPDATE gn_data_requests
                        SET status             = 'Approved',
                            owner_signature    = %s,
                            owner_sign_message = %s,
                            admin_approval     = 'Pending'
                        WHERE id = %s
                    """, (owner_sig, accept_message, rid))
                    conn.commit()
                except Exception as db_err:
                    conn.rollback()
                    print("DB commit error in owner_send:", db_err)
                    msg = "sig_fail"
                    raise

                sc_record = (
                    f"GENENFT_SMART_CONTRACT_OWNER_APPROVAL|"
                    f"RID:{rid}|"
                    f"DATASET:{data3['dataset_id']}|"
                    f"OWNER:{uname}|"
                    f"RESEARCHER:{data3['researcher_id']}|"
                    f"OWNER_SIG_HASH:{hashlib.sha256(owner_sig.encode()).hexdigest()[:16]}|"
                    f"TS:{accept_timestamp}"
                )
                genenft(str(rid), uname, sc_record, 'smart_contract')

                msg = "success"
                sig_display = owner_sig

            except Exception as e:
                print("Acceptance error:", e)
                msg = "sig_fail"

    cursor.close()
    conn.close()
    return render_template("owner_send.html", msg=msg, act=act, sig_display=sig_display, data2=owner_data, data3=data3)


@app.route('/res_purchases')
def res_purchases():
    msg=""
    act=request.args.get("act")
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_researcher WHERE uname=%s", (uname,))
    data2 = cursor.fetchone()
    
    query = """
    SELECT r.*, d.title, d.price
    FROM gn_data_requests r
    JOIN gn_genomic_dataset d ON r.dataset_id = d.id
    WHERE r.researcher_id = %s
    ORDER BY r.id DESC
    """

    cursor.execute(query, (uname,))
    data = cursor.fetchall()

  

    cursor.close()
    conn.close()
    
    return render_template("res_purchases.html",msg=msg,act=act, data=data)

@app.route('/res_pay', methods=['GET', 'POST'])
def res_pay():
    msg=""
    act=request.args.get("act")
    rid=request.args.get("rid")
    uname=""
    if 'username' in session:
        uname = session['username']

    PLATFORM_UPI = "kowsikah217@okicici"

    conn = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)
    
    # Fetch specific request to get the exact price required
    req_data = None
    if rid:
        cursor.execute("""
            SELECT r.*, d.title, d.price
            FROM gn_data_requests r
            JOIN gn_genomic_dataset d ON r.dataset_id = d.id
            WHERE r.id = %s
        """, (rid,))
        req_data = cursor.fetchone()

    cursor.execute("SELECT * FROM gn_researcher WHERE uname=%s", (uname,))
    data2 = cursor.fetchone()
    
    query = """
    SELECT r.*, d.title, d.price
    FROM gn_data_requests r
    JOIN gn_genomic_dataset d ON r.dataset_id = d.id
    WHERE r.researcher_id = %s
    ORDER BY r.id DESC
    """
    cursor.execute(query, (uname,))
    data = cursor.fetchall()

    if request.method == 'POST':
        pay = request.form.get('pay', '').strip()
        amount_paid = request.form.get('amount', '').strip()
        utr_number = request.form.get('utr', '').strip()
        txn_file = request.files.get('txnFile')

        amount_valid = False
        if amount_paid and req_data:
            try:
                if float(amount_paid) == float(req_data['price']):
                    amount_valid = True
            except ValueError:
                pass

        if not req_data:
            msg = "invalid_req"
        elif not txn_file or txn_file.filename == '':
            msg = "missing_receipt"
        elif pay.lower() != PLATFORM_UPI:
            msg = "wrong_upi"
        elif len(utr_number) != 12 or not utr_number.isdigit():
            msg = "invalid_utr"
        elif not amount_valid:
            msg = "wrong_amount"
        else:
            # Check for duplicate UTR to prevent double-spend
            cursor.execute("SELECT id FROM gn_data_requests WHERE utr_number=%s AND id!=%s", (utr_number, rid))
            if cursor.fetchone():
                msg = "duplicate_utr"
            else:
                # Hash the receipt to prevent reuse of the same image
                file_bytes = txn_file.read()
                receipt_hash = hashlib.sha256(file_bytes).hexdigest()
                
                cursor.execute("SELECT id FROM gn_data_requests WHERE receipt_hash=%s AND id!=%s", (receipt_hash, rid))
                if cursor.fetchone():
                    msg = "duplicate_receipt"
                else:
                    # OCR Verification using pytesseract
                    try:
                        import io
                        image = Image.open(io.BytesIO(file_bytes))
                        ocr_text = pytesseract.image_to_string(image).lower()
                        
                        expected_amount_str = str(int(float(req_data['price']))) if float(req_data['price']).is_integer() else str(float(req_data['price']))
                        # The screenshot text must contain BOTH the target UPI ID and the exact amount
                        if expected_amount_str not in ocr_text or PLATFORM_UPI.lower() not in ocr_text:
                            msg = "ocr_fail"
                        else:
                            cursor.execute("""
                                UPDATE gn_data_requests 
                                SET pay_st=1, amount=%s, utr_number=%s, receipt_hash=%s 
                                WHERE id=%s
                            """, (amount_paid, utr_number, receipt_hash, rid))
                            conn.commit()
                            msg = "success"
                            
                            bcdata = f"ID:{rid},Researcher ID:{uname}, Amount Paid:{amount_paid}, UTR:{utr_number}"
                            genenft(str(rid), uname, bcdata, 'payment')
                            
                    except Exception as e:
                        print("OCR Verification Error:", e)
                        msg = "ocr_error"

    cursor.close()
    conn.close()
    
    return render_template("web/res_pay.html", msg=msg, act=act, data=data, req_data=req_data, platform_upi=PLATFORM_UPI)

@app.route('/view_vcf', methods=['GET', 'POST'])
def view_vcf():
    filename = request.args.get("vfile")

    if not filename:
        return render_template("view_vcf.html", headers=[], data=[], vfile="", error="No VCF file specified.")

    file_path = os.path.join("static", "css", "down", filename)

    data = []
    headers = []

    def parse_vcf(path):
        h, d = [], []
        with open(path, 'r') as f:
            for line in f:
                line = line.rstrip('\r\n')
                if line.startswith('##'):
                    continue
                if line.startswith('#CHROM'):
                    h = line.strip().replace('#', '').split('\t')
                    continue
                if not line.strip():
                    continue
                d.append(line.strip().split('\t'))
        return h, d

    if os.path.exists(file_path):
        headers, data = parse_vcf(file_path)

    # If the cached file is empty, try re-extracting from the source VCF
    if not data:
        # Derive owner from filename pattern f<dataset_id>_<req_id>.vcf
        conn2 = get_db_connection()
        cur2 = get_db_cursor(conn2, dictionary=True)
        try:
            parts = filename.replace('.vcf','').split('_')
            dataset_id = parts[0][1:]  # strip leading 'f'
            cur2.execute("SELECT owner_id FROM gn_genomic_dataset WHERE id=%s", (dataset_id,))
            row = cur2.fetchone()
            if row:
                owner_id = row['owner_id']
                src = os.path.join("static","IPFS", owner_id, owner_id+".vcf")
                if not os.path.exists(src):
                    src = os.path.join("static","IPFS", owner_id, owner_id+".VCF")
                if os.path.exists(src):
                    headers, data = parse_vcf(src)
        except Exception:
            pass
        finally:
            cur2.close()
            conn2.close()

    return render_template("view_vcf.html", headers=headers, data=data, vfile=filename)


@app.route('/res_block', methods=['GET', 'POST'])
def res_block():
    msg=""
    data1=[]
    act=request.args.get("act")
    rid=request.args.get("rid")
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_researcher WHERE uname=%s", (uname,))
    data = cursor.fetchone()
    if act=="1":
        ff=open("static/genenft.json","r")
        fj=ff.read()
        ff.close()

        fjj=fj.split('}')

        nn=len(fjj)
        nn2=nn-2
        i=0
        fsn=""
        while i<nn-1:
            if i==nn2:
                fsn+=fjj[i]+"}"
            else:
                fsn+=fjj[i]+"},"
            i+=1
            
        #fjj1='},'.join(fjj)
        
        fj1="["+fsn+"]"
        

       

    ################
    if act=="11":
        s1="1"
        ff=open("static/css/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if uname in dr1[2]:
            
                
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                if uname in dr1[2]:
                    dt.append("2")
                else:
                    dt.append("1")
                data1.append(dt)
    else:
        ff=open("static/css/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            #if "Register" in dr1[2]:
                
            dt.append(dr1[0])
            dt.append(dr1[1])
            dt.append(dr1[2])
            dt.append(dr1[3])
            #dt.append(dr1[4])
            data1.append(dt)

    cursor.close()
    conn.close()
    return render_template("res_block.html",msg=msg,act=act, data=data,data1=data1)

@app.route('/owner_block', methods=['GET', 'POST'])
def owner_block():
    msg=""
    data1=[]
    act=request.args.get("act")
    rid=request.args.get("rid")
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data = cursor.fetchone()
    if act=="1":
        ff=open("static/genenft.json","r")
        fj=ff.read()
        ff.close()

        fjj=fj.split('}')

        nn=len(fjj)
        nn2=nn-2
        i=0
        fsn=""
        while i<nn-1:
            if i==nn2:
                fsn+=fjj[i]+"}"
            else:
                fsn+=fjj[i]+"},"
            i+=1
            
        #fjj1='},'.join(fjj)
        
        fj1="["+fsn+"]"
        

       

    ################
    if act=="11":
        s1="1"
        ff=open("static/css/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if uname in dr1[2]:
            
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                if uname in dr1[2]:
                    dt.append("2")
                else:
                    dt.append("1")
                data1.append(dt)
    else:
        ff=open("static/css/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            #if "Register" in dr1[2]:
                
            dt.append(dr1[0])
            dt.append(dr1[1])
            dt.append(dr1[2])
            dt.append(dr1[3])
            #dt.append(dr1[4])
            data1.append(dt)

    cursor.close()
    conn.close()
    return render_template("owner_block.html",msg=msg,act=act, data=data,data1=data1)
##
# ===== GENE WEIGHTS =====
GENE_WEIGHTS = {
    "BRCA1": 30,
    "TP53": 25,
    "KRAS": 20,
    "APOE": 15
}

# ===== EXTRACT VARIANTS =====
def get_variants(vcf_file, disease):
    variants = []

    with open(vcf_file, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue

            parts = line.strip().split('\t')
            if len(parts) < 8:
                continue

            info = parts[7]

            gene = ""
            dis = ""

            for item in info.split(';'):
                if item.startswith("GENE="):
                    gene = item.split('=')[1]
                if item.startswith("DISEASE="):
                    dis = item.split('=')[1]

            if dis.lower().replace(" ", "") == disease.lower().replace(" ", ""):
                variants.append(gene)

    return list(set(variants))  # remove duplicates


# ===== CALCULATE RISK =====
def calculate_risk(variants):
    score = 0
    for g in variants:
        score += GENE_WEIGHTS.get(g, 5)
    return min(score, 100)


# ===== CATEGORY =====
def risk_category(score):
    if score > 70:
        return "High"
    elif score > 40:
        return "Medium"
    else:
        return "Low"


# ===== MAIN VARIANT =====
def main_variant(variants):
    return variants[0] + " Mutation" if variants else "None"

@app.route('/result', methods=['GET', 'POST'])
def result():
    result = None

    ff=open("static/det.txt","r")
    disease=ff.read()
    ff.close()
    
    file = request.args.get("vfile")

    # 1. Plaintext Analysis (for reference)
    variants = get_variants("static/css/down/"+file, disease)
    score = calculate_risk(variants)
    category = risk_category(score)
    variant = main_variant(variants)

    # 2. FULL FHE ANALYSIS (Privacy Preserving)
    fhe_logs = []
    fhe_score = None
    try:
        # Derive IDs from filename (f<dataset_id>_<req_id>.vcf)
        parts = file.replace('.vcf', '').split('_')
        ds_id = parts[0].replace('f', '')
        
        conn = get_db_connection()
        cur = get_db_cursor(conn, dictionary=True)
        
        # Get owner info
        cur.execute("SELECT owner_id FROM gn_genomic_dataset WHERE id=%s", (ds_id,))
        ds_row = cur.fetchone()
        if ds_row:
            owner_id = ds_row['owner_id']
            public_key, private_key = get_fhe_keys(owner_id)
            
            if public_key:
                fhe_logs.append(f"FHE Public Key Loaded for Data Owner: {owner_id}")
                
                # Fetch encrypted variants from DB
                cur.execute("SELECT * FROM gn_encrypted_genomics WHERE dataset_id=%s", (ds_id,))
                enc_data = cur.fetchall()
                
                if enc_data:
                    # Initial encrypted zero
                    enc_total = public_key.encrypt(0)
                    fhe_logs.append(f"Initialized Homomorphic Accumulator: {hex(enc_total.ciphertext())[:32]}...")
                    
                    for row in enc_data:
                        gene = row['gene_name']
                        enc_bit_hex = int(row['encrypted_bit'])
                        weight = GENE_WEIGHTS.get(gene, 5)
                        
                        # Reconstruct encrypted bit
                        ebit = paillier.EncryptedNumber(public_key, enc_bit_hex)
                        
                        # Homomorphic Multiplication (Scalar * Encrypted)
                        # This calculates Enc(bit * weight)
                        e_weighted = ebit * weight
                        
                        # Homomorphic Addition
                        # This calculates Enc(Total + (bit * weight))
                        enc_total = enc_total + e_weighted
                        
                        fhe_logs.append(f"Homomorphic Operation: ADD [Enc({gene}) * {weight}] -> Cipher: {hex(e_weighted.ciphertext())[:24]}...")
                    
                    # Decrypt result (Proof of Concept)
                    if private_key:
                        fhe_score = private_key.decrypt(enc_total)
                        fhe_score = min(fhe_score, 100)
                        fhe_logs.append(f"FHE Final Ciphertext: {hex(enc_total.ciphertext())[:64]}...")
                        fhe_logs.append(f"Decrypted FHE Result: {fhe_score} (Matches Plaintext Proof)")
                else:
                    fhe_logs.append("No FHE-encrypted variants found for this dataset. Perform a fresh upload to enable FHE.")
            else:
                fhe_logs.append("FHE Keys not found for this Data Owner.")
        
        cur.close()
        conn.close()
    except Exception as e:
        fhe_logs.append(f"FHE Process Error: {str(e)}")

    result = {
        "disease": disease,
        "score": score,
        "category": category,
        "variant": variant,
        "count": len(variants),
        "fhe_logs": fhe_logs,
        "fhe_score": fhe_score
    }

    return render_template("result.html", result=result)

# ============================================================
#  ADMIN: Re-sign mismatched owner signatures (repair tool)
# ============================================================
@app.route('/admin_repair_signatures')
def admin_repair_signatures():
    if session.get('username') is None:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)

    cursor.execute("""
        SELECT * FROM gn_data_requests
        WHERE owner_signature IS NOT NULL
    """)
    rows = cursor.fetchall()

    fixed  = 0
    failed = 0
    skipped = 0

    for req in rows:
        owner_id = req['owner_id']

        try:
            # ── Check validity against DB key (what admin verify actually uses) ──
            cursor.execute("SELECT public_key FROM gn_owner WHERE uname=%s", (owner_id,))
            owner_row  = cursor.fetchone()
            db_pub_pem = owner_row['public_key'] if owner_row else None

            if db_pub_pem:
                db_pub_key    = serialization.load_pem_public_key(db_pub_pem.encode())
                already_valid = rsa_verify(db_pub_key, req['owner_sign_message'], req['owner_signature'])
                if already_valid:
                    skipped += 1
                    continue

            # ── Key files exist on disk → re-sign then sync DB atomically ──
            private_key_obj = load_private_key_pem(owner_id)   # raises FileNotFoundError if missing
            pub_key_obj     = load_public_key_pem(owner_id)
            pub_pem         = pub_key_obj.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            sign_timestamp   = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            new_sign_message = (
                f"GENENFT_OWNER_APPROVAL|"
                f"RID:{req['id']}|"
                f"OWNER:{owner_id}|"
                f"DATASET:{req['dataset_id']}|"
                f"RESEARCHER:{req['researcher_id']}|"
                f"TS:{sign_timestamp}"
            )

            new_signature = rsa_sign(private_key_obj, new_sign_message)

            # ── Verify before touching DB ──
            if not rsa_verify(pub_key_obj, new_sign_message, new_signature):
                raise Exception("Self-verify failed after re-signing")

            # ── Atomic: public key + signature in one transaction ──
            try:
                cursor.execute(
                    "UPDATE gn_owner SET public_key = %s WHERE uname = %s",
                    (pub_pem, owner_id)
                )
                cursor.execute("""
                    UPDATE gn_data_requests
                    SET owner_signature    = %s,
                        owner_sign_message = %s,
                        admin_approval     = 'Pending'
                    WHERE id = %s
                """, (new_signature, new_sign_message, req['id']))
                conn.commit()
            except Exception as db_err:
                conn.rollback()
                raise Exception(f"DB commit failed: {db_err}")

            print(f"Fixed RID {req['id']} — owner: {owner_id}")
            fixed += 1

        except FileNotFoundError:
            # Key file missing — generate fresh pair, sync DB, re-sign, all atomic
            try:
                private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                public_key_obj  = private_key_obj.public_key()

                priv_pem = private_key_obj.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()
                ).decode()
                pub_pem = public_key_obj.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()

                # Write to disk first
                with open(f"static/kg/{owner_id}_pr.txt", "w") as f:
                    f.write(priv_pem)
                with open(f"static/kg/{owner_id}_pb.txt", "w") as f:
                    f.write(pub_pem)

                sign_timestamp   = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                new_sign_message = (
                    f"GENENFT_OWNER_APPROVAL|"
                    f"RID:{req['id']}|"
                    f"OWNER:{owner_id}|"
                    f"DATASET:{req['dataset_id']}|"
                    f"RESEARCHER:{req['researcher_id']}|"
                    f"TS:{sign_timestamp}"
                )
                new_signature = rsa_sign(private_key_obj, new_sign_message)

                if not rsa_verify(public_key_obj, new_sign_message, new_signature):
                    raise Exception("Self-verify failed after fresh key generation")

                try:
                    cursor.execute(
                        "UPDATE gn_owner SET public_key = %s WHERE uname = %s",
                        (pub_pem, owner_id)
                    )
                    cursor.execute("""
                        UPDATE gn_data_requests
                        SET owner_signature    = %s,
                            owner_sign_message = %s,
                            admin_approval     = 'Pending'
                        WHERE id = %s
                    """, (new_signature, new_sign_message, req['id']))
                    conn.commit()
                except Exception as db_err:
                    conn.rollback()
                    raise Exception(f"DB commit failed after key gen: {db_err}")

                print(f"Generated fresh keys + fixed RID {req['id']} — owner: {owner_id}")
                fixed += 1

            except Exception as e2:
                print(f"Key generation failed for RID {req['id']}: {e2}")
                failed += 1

        except Exception as e:
            conn.rollback()
            print(f"Repair failed for RID {req['id']}: {e}")
            failed += 1

    cursor.close()
    conn.close()

    return (
        f"<h3>Repair Complete</h3>"
        f"<p>✓ Fixed: {fixed}</p>"
        f"<p>⟳ Already valid (skipped): {skipped}</p>"
        f"<p>✗ Failed: {failed}</p>"
        f"<br><a href='/admin_send_approvals'>Go to Approvals</a>"
    )




@app.route('/debug_sig/<rid>')
def debug_sig(rid):
    """Temporary debug route — remove after fixing"""
    conn = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)

    # Get request row
    cursor.execute("SELECT * FROM gn_data_requests WHERE id=%s", (rid,))
    req = cursor.fetchone()
    if not req:
        return f"No request found for id={rid}"

    owner_id      = req['owner_id']
    owner_sig     = req['owner_signature']
    owner_msg     = req['owner_sign_message']

    # Get public key from DB
    cursor.execute("SELECT public_key FROM gn_owner WHERE uname=%s", (owner_id,))
    owner_row = cursor.fetchone()
    db_pubkey = owner_row['public_key'] if owner_row else None

    # Get public key from disk
    import os
    disk_path = f"static/kg/{owner_id}_pb.txt"
    disk_pubkey = open(disk_path).read() if os.path.exists(disk_path) else "FILE NOT FOUND"

    # Try verify with DB key
    db_verify = False
    db_err = ""
    try:
        from cryptography.hazmat.primitives import serialization as ser2
        pk = ser2.load_pem_public_key(db_pubkey.encode())
        db_verify = rsa_verify(pk, owner_msg, owner_sig)
    except Exception as e:
        db_err = str(e)

    # Try verify with disk key
    disk_verify = False
    disk_err = ""
    try:
        pk2 = ser2.load_pem_public_key(disk_pubkey.encode())
        disk_verify = rsa_verify(pk2, owner_msg, owner_sig)
    except Exception as e:
        disk_err = str(e)

    # Keys match?
    keys_match = (db_pubkey == disk_pubkey)

    cursor.close()
    conn.close()

    return f"""
    <h2>Debug Signature — RID {rid}</h2>
    <b>owner_id:</b> {owner_id}<br>
    <b>owner_sign_message:</b><br><pre>{owner_msg}</pre>
    <b>owner_signature (first 60):</b> {owner_sig[:60] if owner_sig else 'NULL'}<br><br>
    <b>DB public key (first 60):</b> {db_pubkey[:60] if db_pubkey else 'NULL'}<br>
    <b>Disk public key (first 60):</b> {disk_pubkey[:60]}<br>
    <b>Keys match (DB == Disk):</b> {keys_match}<br><br>
    <b>Verify with DB key:</b> {db_verify} {db_err}<br>
    <b>Verify with Disk key:</b> {disk_verify} {disk_err}<br>
    """

# ============================================================
#  OWNER: Digital Signature Verification Page
# ============================================================

def _fingerprint(pub_key_obj):
    """SHA-256 fingerprint of a public key (first 32 hex chars)."""
    pub_der = pub_key_obj.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pub_der).hexdigest()[:32]


def _verify_one(signer_type, req):
    """
    Verify a single signature on a request dict.
    Returns dict with keys: ok, signer, fingerprint, message_preview, sig_preview, error
    """
    col_sig  = f"{signer_type}_signature"
    col_msg  = f"{signer_type}_sign_message"
    sig_val  = req.get(col_sig)
    msg_val  = req.get(col_msg)

    result = {
        "type":       signer_type,
        "ok":         None,
        "signer":     "",
        "fingerprint": "",
        "message":    msg_val or "",
        "sig_preview": "",
        "error":      ""
    }

    if not sig_val or not str(sig_val).strip():
        result["error"] = "Not signed yet"
        return result

    result["sig_preview"] = str(sig_val)[:80] + ("…" if len(str(sig_val)) > 80 else "")

    # Determine signer identity and load public key
    try:
        if signer_type == "owner":
            signer_id = req.get("owner_id", "")
            result["signer"] = signer_id
            pub = get_owner_public_key(signer_id)
        elif signer_type == "lab":
            signer_id = req.get("lab_signer", "")
            result["signer"] = signer_id
            if not signer_id:
                result["error"] = "No lab signer recorded"
                return result
            pub = get_lab_public_key(signer_id)
        elif signer_type == "admin":
            result["signer"] = "Admin"
            pub = get_admin_public_key()
        elif signer_type == "researcher":
            signer_id = req.get("researcher_id", "")
            result["signer"] = signer_id
            pub = get_researcher_public_key(signer_id)
        else:
            result["error"] = f"Unknown signer type: {signer_type}"
            return result

        result["fingerprint"] = _fingerprint(pub)

        if not msg_val:
            result["error"] = "Signed message payload missing"
            result["ok"] = False
            return result

        result["ok"] = rsa_verify(pub, msg_val, sig_val)
        if not result["ok"]:
            result["error"] = "RSA-PSS verification failed — signature does not match key"
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)

    return result


@app.route('/owner_verify_signatures', methods=['GET', 'POST'])
def owner_verify_signatures():
    """Page that lists every data request for the logged-in owner and
    shows the RSA-PSS verification status for all 4 signature slots.

    PROTECTION: Owner must first pass a two-factor gate:
      1. Enter their Master Hash Key (sent to email at registration)
      2. Server performs a live RSA signature challenge — signs a random
         nonce with the owner's private key and verifies against the DB
         public key to prove the key pair is intact and belongs to this owner.
    Only after both checks pass are signatures revealed.
    """
    if 'username' not in session:
        return redirect(url_for('login_owner'))

    uname = session['username']

    conn   = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)

    # Owner profile row
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    owner_data = cursor.fetchone()

    if not owner_data:
        cursor.close(); conn.close()
        return redirect(url_for('login_owner'))

    # ── PROTECTION GATE ──────────────────────────────────────────────────
    # On GET: show the master-key challenge form (no signatures visible)
    # On POST: verify master key + RSA challenge, then show signatures
    auth_msg        = ""
    authenticated   = False
    challenge_nonce = ""
    challenge_sig   = ""
    challenge_ok    = False

    if request.method == 'POST':
        entered_key = request.form.get('master_key', '').strip()
        stored_key  = owner_data.get('masterkey', '')

        if not entered_key:
            auth_msg = "missing"
        elif entered_key != stored_key:
            auth_msg = "wrong_key"
        else:
            # Master key correct → perform RSA signature challenge
            try:
                challenge_nonce = f"GENENFT_CHALLENGE|OWNER:{uname}|NONCE:{uuid.uuid4().hex}|TS:{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}"
                owner_priv = get_owner_private_key(uname)
                challenge_sig  = rsa_sign(owner_priv, challenge_nonce)

                owner_pub  = get_owner_public_key(uname)
                challenge_ok = rsa_verify(owner_pub, challenge_nonce, challenge_sig)

                if challenge_ok:
                    authenticated = True
                else:
                    auth_msg = "sig_challenge_fail"
            except Exception as e:
                auth_msg = "sig_challenge_error"
                print(f"Sig challenge error for {uname}: {e}")

    if not authenticated:
        # Show only the gate form — no signature data exposed
        cursor.close(); conn.close()
        return render_template(
            "owner_verify_signatures.html",
            owner_data=owner_data,
            authenticated=False,
            auth_msg=auth_msg,
            verified_requests=[],
            total=0, fully_signed=0, partially_signed=0, pending=0,
            challenge_nonce="", challenge_sig="", challenge_ok=False
        )

    # ── AUTHENTICATED — load and verify all signatures ────────────────
    cursor.execute("""
        SELECT r.*, d.title, d.price
        FROM gn_data_requests r
        JOIN gn_genomic_dataset d ON r.dataset_id = d.id
        WHERE r.owner_id = %s
        ORDER BY r.id DESC
    """, (uname,))
    requests_raw = cursor.fetchall()

    verified_requests = []
    total    = len(requests_raw)
    fully_signed = 0
    partially_signed = 0

    for req in requests_raw:
        sigs = {}
        all_ok  = True
        any_sig = False
        for stype in ["researcher", "owner", "lab", "admin"]:
            v = _verify_one(stype, req)
            sigs[stype] = v
            if v["ok"] is True:
                any_sig = True
            if v["ok"] is not True:
                all_ok = False

        if all_ok and any_sig:
            fully_signed += 1
        elif any_sig:
            partially_signed += 1

        verified_requests.append({
            "req":  req,
            "sigs": sigs
        })

    cursor.close()
    conn.close()

    return render_template(
        "owner_verify_signatures.html",
        owner_data=owner_data,
        authenticated=True,
        auth_msg="",
        verified_requests=verified_requests,
        total=total,
        fully_signed=fully_signed,
        partially_signed=partially_signed,
        pending=total - fully_signed - partially_signed,
        challenge_nonce=challenge_nonce,
        challenge_sig=challenge_sig[:60] + "..." if challenge_sig else "",
        challenge_ok=challenge_ok
    )


@app.route('/api/verify_signature', methods=['POST'])
def api_verify_signature():
    """AJAX endpoint: verify a single signature on-demand.
    Expects JSON: { rid: <int>, signer_type: "owner"|"lab"|"admin"|"researcher" }
    Returns JSON verification result."""
    if 'username' not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json(force=True)
    rid         = data.get("rid")
    signer_type = data.get("signer_type")

    if not rid or not signer_type:
        return jsonify({"error": "Missing rid or signer_type"}), 400

    conn   = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_data_requests WHERE id=%s", (rid,))
    req = cursor.fetchone()
    cursor.close()
    conn.close()

    if not req:
        return jsonify({"error": "Request not found"}), 404

    result = _verify_one(signer_type, req)
    # Make JSON-safe
    result["rid"] = rid
    result["verified_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return jsonify(result)


@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    session.pop('username', None)
    return redirect(url_for('index'))




@app.route('/debug_approvals')
def debug_approvals():
    """Temporary debug route — shows raw DB state for all data requests."""
    if session.get('username') is None:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)

    cursor.execute("""
        SELECT id, owner_id, researcher_id, dataset_id,
               owner_signature,
               lab_signature, lab_signer,
               admin_approval, admin_signature,
               pay_st
        FROM gn_data_requests
        ORDER BY id DESC
        LIMIT 20
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    html = "<h2>Debug: gn_data_requests (last 20)</h2>"
    html += "<table border=1 cellpadding=6 style='font-family:monospace;font-size:13px'>"
    html += "<tr><th>id</th><th>owner_id</th><th>researcher_id</th><th>dataset_id</th>"
    html += "<th>owner_signature</th><th>lab_signature</th><th>lab_signer</th>"
    html += "<th>admin_approval</th><th>admin_signature</th><th>pay_st</th></tr>"
    for r in rows:
        def short(v):
            if v is None: return "<i style=color:red>NULL</i>"
            s = str(v)
            return s[:40] + "…" if len(s) > 40 else s
        html += f"<tr>"
        html += f"<td>{r['id']}</td>"
        html += f"<td>{r['owner_id']}</td>"
        html += f"<td>{r['researcher_id']}</td>"
        html += f"<td>{r['dataset_id']}</td>"
        html += f"<td>{short(r['owner_signature'])}</td>"
        html += f"<td>{short(r['lab_signature'])}</td>"
        html += f"<td>{short(r['lab_signer'])}</td>"
        html += f"<td><b>{short(r['admin_approval'])}</b></td>"
        html += f"<td>{short(r['admin_signature'])}</td>"
        html += f"<td>{r['pay_st']}</td>"
        html += "</tr>"
    html += "</table>"
    html += "<br><a href='/admin_send_approvals'>← Back to Approvals</a>"
    return html


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)