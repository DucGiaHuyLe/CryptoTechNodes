import datetime
import json
import hashlib
import socket
from time import time
from datetime import datetime
from urllib.parse import urlparse
import requests
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import binascii
from uuid import uuid4
from transaction import Transaction
from datetime import datetime
from wallet import Wallet

class Blockchain:
    """
    This class represents the blockchain and includes methods for managing and validating the chain,
    creating new blocks, and handling transactions.
    """
    def __init__(self, port):
        """
        Initialize a new blockchain, with an empty list of current transactions, a set of nodes,
        a unique node identifier, and a hardcoded genesis block added to the chain.
        """
        self.chain = []
        self.current_transactions = []
        self.nodes = set()
        self.node_identifier = str(uuid4()).replace('-', '')

        # Create the hardcoded genesis block
        genesis_block = {
            'index': 1,
            'timestamp': 1506057125.900785,
            'transactions': [],
            'proof': 100,
            'previous_hash': "1",
            'hash': "Genesis Block"
        }

        self.chain.append(genesis_block)
        local_ip = self.get_local_ip()
        parsed_url = urlparse(f"http://{local_ip}:{port}")
        self.nodes.add(parsed_url.netloc)

        if port == 5000:
            self.blockchain_name = "FC"
        elif port == 5050:
            self.blockchain_name = "TKC"
        elif port == 6000:
            self.blockchain_name = "BTC"
        elif port == 6050:
            self.blockchain_name = "CTC"


    def export_blockchain(self):
        """
        Export the blockchain data to a .txt file with the current date in the filename.
        """
        filename = f"{self.blockchain_name}_blockchain_backup.txt"
        
        with open(filename, 'w') as file:
            file.write(json.dumps(self.chain) + "\n")
        print(f"Blockchain exported to {filename}")

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # we do not actually connect, we just use this to determine the most appropriate network interface to use
        try:
            # doesn't have to be reachable, its purpose is to just fetch the local endpoint address
            s.connect(('10.254.254.254', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def get_public_ip(self):
        try:
            response = requests.get('https://httpbin.org/ip')
            return response.json()['origin']
        except Exception as e:
            print(f"Error occurred: {e}")
            return None

    def sort_pending_txn(self):
        """
        Sort the pending transactions in descending order based on the transaction fee.
        """
        self.current_transactions = sorted(
            self.current_transactions, 
            key=lambda txn: txn.to_dict()['transaction_fee'], 
            reverse=True
        )

    def set_chain(self, new_chain):
        self.chain = new_chain

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': [tx.to_dict() for tx in self.current_transactions],
            'proof': proof,
            'previous_hash': self.hash(self.chain[len(self.chain)-1]),
        }

        block['hash'] = self.hash(block)
        self.current_transactions = []
        self.chain.append(block)
        for node in self.nodes:
            jsonrpc_url = f'http://{node}/jsonrpc'  # JSON-RPC endpoint

            # Prepare JSON-RPC request for broadcasting block
            broadcast_request_json = {
                "jsonrpc": "2.0",
                "method": "broadcast_block",
                "params": {
                    'block': block
                },
                "id": 1  # The request ID can be any integer
            }

            # Prepare JSON-RPC request for removing pending transactions
            remove_request_json = {
                "jsonrpc": "2.0",
                "method": "remove_txn",
                "params": {},
                "id": 2  # The request ID can be any integer
            }

            try:
                # Send JSON-RPC requests
                bc_response = requests.post(jsonrpc_url, json=broadcast_request_json, timeout=5)
                if bc_response.status_code != 200 or 'error' in bc_response.json():
                    print('Block declined, needs resolving')
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                continue
        
            try:
                rt_response = requests.post(jsonrpc_url, json=remove_request_json, timeout=5)
                if rt_response.status_code != 200 or 'error' in rt_response.json():
                    print(rt_response.json()['error']['message'])
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                continue

        return block


    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block.

        :param block: <dict> Block
        :return: <str>
        """
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def new_transaction(self, sender, recipient, amount, signature, sender_wallet_address, transaction_fee):
        """
        Creates a new transaction to go into the next mined Block.

        :param sender: <str> Address of the Sender
        :param recipient: <str> Address of the Recipient
        :param amount: <int> Amount
        :param signature: <str> Signature of the transaction
        :param sender_wallet_address: <str> Wallet address of the Sender
        :return: <int> The index of the Block that will hold this transaction
        """
        transaction = Transaction(sender, recipient, amount, signature, sender_wallet_address, transaction_fee)
        self.current_transactions.append(transaction)
        return transaction

    def block_difficulty(self, block):
        block_hash = self.hash(block)
        return block_hash.count('0', 0, 4)  # Count the number of leading zeroes

    def chain_difficulty(self, chain=None):
        if chain is None:
            chain = self.chain
        return sum(self.block_difficulty(block) for block in chain)

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        """
        Simple Proof of Work Algorithm.

        - Find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
        - p is the previous proof, and p' is the new proof

        :param last_proof: <int>
        :return: <int>
        """
        proof = 0
        while self.valid_proof(last_proof, proof, self.hash(self.last_block)) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash=None):
        if last_hash is None:
            guess = f'{last_proof}{proof}'.encode()
        else:
            guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    # Verifies by checking whether sender has sufficient coins or not
    @staticmethod
    def verify_transaction(transaction, get_pending_balance, check_funds=True):
        if check_funds:
            sender_balance = get_pending_balance(transaction.sender_wallet_address)
            return sender_balance >= 0 and Wallet().verify_transaction(transaction)
        else:
            return Wallet().verify_transaction(transaction)
            
    def get_pending_balance(self, wallet_address):
        """
        Calculate and return the balance for a wallet considering the transactions in the blockchain 
        and the pending transactions.

        :param wallet_address: <str> Wallet address to get balance of
        :return: <int> Balance of the wallet
        """
        balance = self.get_balance(wallet_address)
        for transaction in self.current_transactions:
            if transaction.sender_wallet_address == wallet_address:
                balance -= (transaction.amount + transaction.transaction_fee)
        return balance


        
    def get_other_chains(self):
        other_chains = []
        for node in self.nodes:
            jsonrpc_url = f'http://{node}/jsonrpc'  # JSON-RPC endpoint
            
            # Prepare JSON-RPC request for full_chain method
            request_json = {
                "jsonrpc": "2.0",
                "method": "full_chain",
                "params": {},  # No parameters are required for this method
                "id": 1  # The request ID can be any integer
            }

            try:
                # Send JSON-RPC request
                response = requests.post(jsonrpc_url, json=request_json, timeout=5)
                if response.status_code == 200:
                    response_json = response.json()
                    if 'error' not in response_json:
                        chain = response_json['result']['chain']
                        other_chains.append(chain)
                    else:
                        print(f'Error getting chain from {node}: {response_json["error"]["message"]}')
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                print(f'Could not connect to {node}')

        return other_chains


    def register_node(self, address):
        parsed_url = urlparse(address)
        
        # Check if node already exists in the set
        if parsed_url.netloc in self.nodes:
            print(f"Node {parsed_url.netloc} is already registered.")
            return False

        # If we're going to exceed 10 nodes, remove the second to last node
        if len(self.nodes) >= 10:
            node_to_remove = list(self.nodes)[-2]  # Don't delete the last one because it is the local ip node
            self.nodes.remove(node_to_remove)
            print(f"Removed node {node_to_remove} due to node limit.")

        self.nodes.add(parsed_url.netloc)
        return True


    def valid_chain(self, chain):
        # Check if the genesis block matches
        if self.hash(chain[0]) != self.hash(self.chain[0]):
            print(f"Invalid genesis block: {self.hash(chain[0])} != {self.hash(self.chain[0])}")
            return False


        # Check the validity of each block in the chain
        for i in range(1, len(chain)):
            block = chain[i]
            last_block = chain[i - 1]
            last_block_hash = self.hash(last_block)

            # Check the previous hash
            if block['previous_hash'] != last_block_hash:
                print(f"Invalid previous hash: {block['previous_hash']} != {last_block_hash}")
                return False

            # Check the proof of work
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                print(f"Invalid proof: {last_block['proof']} -> {block['proof']} (hash: {last_block_hash})")
                return False

            # Check the signatures of each transaction in the block
            for transaction_dict in block['transactions']:
                if transaction_dict['sender'] != "0":
                    transaction = Transaction(**transaction_dict)
                    sender, recipient, amount, signature = (
                        transaction.sender,
                        transaction.recipient,
                        transaction.amount,
                        transaction.signature,
                    )
                    transaction_copy = transaction.to_dict()
                    transaction_copy.pop('signature', None)
                    if not self.verify_signature(sender, signature, transaction_copy):
                        print(f"Invalid signature: {signature} for transaction: {transaction_copy}")
                        return False

        return True

    def resolve_conflicts(self):
        """
        This is our Consensus Algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: <bool> True if our chain was replaced, False if not
        """
        other_chains = self.get_other_chains()
        if not other_chains:
            print("No other chains found")
            return False

        max_length = len(self.chain)
        new_chain = None

        for chain in other_chains:
            if len(chain) > max_length and self.valid_chain(chain):
                max_length = len(chain)
                new_chain = chain

        if new_chain:
            self.chain = new_chain
            print("Chain replaced")
            return True

        print("Chain not replaced")
        return False
    
    def get_balance(self, wallet_address):
        """
        Calculate and return the balance for a wallet.

        :param wallet_address: <str> Wallet address to get balance of
        :return: <int> Balance of the wallet
        """
        balance = 0

        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['sender_wallet_address'] == wallet_address:
                    balance -= (transaction['amount'] + transaction['transaction_fee'])
                if transaction['recipient'] == wallet_address:
                    balance += transaction['amount']
        return balance


    def get_transactions(self, wallet_address):
        """
        Retrieve transactions involving the given wallet address and sort them by timestamp in descending order.

        :param wallet_address: <str> Wallet address to search for in transactions
        :return: <list> List of transactions involving the wallet_address, sorted by timestamp
        """
        transactions = []

        # Search through the confirmed transactions on the blockchain
        for block in self.chain:
            block_hash = block['hash']
            for transaction in block['transactions']:
                if transaction['sender_wallet_address'] == wallet_address or transaction['recipient'] == wallet_address:
                    transaction_with_status = transaction.copy()  # create a copy to avoid mutating the original transaction
                    transaction_with_status['status'] = 'confirmed'  # add the 'status' key to the transaction dictionary
                    transaction_with_status['block_hash'] = block_hash
                    transactions.append(transaction_with_status)

        # Now search through the pending transactions
        for transaction in self.current_transactions:
            transaction_dict = transaction.to_dict()  # assuming that the to_dict() method gives us a dictionary representation of the transaction
            if transaction_dict['sender_wallet_address'] == wallet_address or transaction_dict['recipient'] == wallet_address:
                transaction_dict['status'] = 'pending'  # add the 'status' key to the transaction dictionary
                transaction_dict['block_hash'] = ''
                transactions.append(transaction_dict)

        # Sort the transactions by timestamp in descending order
        transactions = sorted(transactions, key=lambda x: datetime.strptime(x['timestamp'], '%d-%m-%Y %H:%M:%S %Z%z'), reverse=True)

        return transactions


    def verify_signature(self, sender_public_key_hex, signature_hex, transaction):
        sender_public_key_bytes = binascii.unhexlify(sender_public_key_hex)
        sender_public_key = VerifyingKey.from_string(sender_public_key_bytes, curve=SECP256k1)
        signature = binascii.unhexlify(signature_hex)
        transaction_data = json.dumps(transaction, sort_keys=True).encode()

        try:
            return sender_public_key.verify(signature, transaction_data)
        except BadSignatureError:
            return False

    def add_new_node(self, new_node):
        success = self.register_node(new_node)
        if success == False:
            return
      
        # Sync the blockchain for new nodes
        request_json = {
            "jsonrpc": "2.0",
            "method": "sync_chain",
            "params": {"chain": self.chain},
            "id": 1  # The request ID can be any integer
        }

        try:
            # Send JSON-RPC request
            response = requests.post(f"{new_node}/jsonrpc", json=request_json, timeout=5)
            if response.status_code != 200 or 'error' in response.json():
                print(f'{new_node}: Error when syncing with other nodes. Status code: {response.status_code}, Response: {response.json()}')
                return False
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            # Silently fail upon connection errors or timeouts
            pass

        for node in self.nodes:
            url = f'http://{node}/jsonrpc'  # JSON-RPC endpoint

            # Prepare JSON-RPC request
            request_json = {
                "jsonrpc": "2.0",
                "method": "broadcast_node",
                "params": {
                    "node": new_node
                },
                "id": 1  # The request ID can be any integer
            }

            try:
                # Send JSON-RPC request
                response = requests.post(url, json=request_json, timeout=5)
                if response.status_code != 200 or 'error' in response.json():
                    print(f'{node}: Error when adding new node to the network')
                    return False
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                # Silently fail upon connection errors or timeouts
                pass
        
        return True


    # Creating a Chain of Data( Append a new value as well as the last blockchain value to the blockchain )
    def add_transaction(self, sender, recipient, signature, amount, sender_wallet_address, transaction_fee, is_receiving=False):
        """
        Adds a new transaction to the list of transactions.

        :param sender: <str> Address of the Sender
        :param recipient: <str> Address of the Recipient
        :param signature: <str> Signature of the transaction
        :param amount: <int> Amount
        :param sender_wallet_address: <str> Wallet address of the Sender
        :param is_receiving: <bool> Whether the node is on the receiving end of the transaction
        :return: <bool> True if transaction was successfully added, or False if not
        """
        if not is_receiving:
            for node in self.nodes:
                url = f'http://{node}/jsonrpc'  # JSON-RPC endpoint

                # Prepare JSON-RPC request
                request_json = {
                    "jsonrpc": "2.0",
                    "method": "broadcast_transaction",
                    "params": {
                        "sender": sender, 
                        "recipient": recipient, 
                        "amount": amount, 
                        "signature": signature,
                        "sender_wallet_address": sender_wallet_address,
                        "transaction_fee": transaction_fee
                    },
                    "id": 1  # The request ID can be any integer
                }

                try:
                    response = requests.post(url, json=request_json, timeout=5)
                    if response.status_code == 200 and 'result' in response.json():
                        return response.json().get('result', {}).get('transaction', {})
                    else:
                        print('Transaction declined, needs resolving')
                        return None
                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                    continue  
        return { "status": "success" }
