import argparse
import sys
from flask import Flask, jsonify, request, Response
from jsonrpcserver import method, Success, Error, dispatch
from blockchain import Blockchain
from wallet import Wallet
import requests
import json
from transaction import Transaction
from datetime import datetime
import upnpclient
import getpass

app = Flask(__name__)

@method
def mine(coin, miner_address = None, private_key = None):
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    COIN_REWARD_MAPPING = {
        "FC": 1000.0,  #FC reward
        "TKC": 2400.0, #TKC reward
        "BTC": 6.25,   #BTC reward
        "CTC": 2000.0  #CTC Reward
    } 

    if coin not in ["FC", "TKC", "BTC", "CTC"]:
        return Error('InternalError', message='Invalid coin select')

    # Sort pending transactions
    blockchain.sort_pending_txn()
    txn_fee = float(0)

    # Iterate over a copy of the current transactions
    for transaction in blockchain.current_transactions:
        success = blockchain.verify_transaction(transaction, blockchain.get_pending_balance)
        txn_fee += float(transaction.transaction_fee)
        # If not successful, remove the transaction
        if not success:
            blockchain.current_transactions.remove(transaction)

    if coin == "BTC" or coin == "CTC":
        if miner_address is not None and private_key is not None:
            reward_transaction = wallet.create_reward_transaction_for_sommeone(private_key, miner_address, COIN_REWARD_MAPPING[coin] + txn_fee)
        else:
            return Error('InternalError', message='Need wallet addrress and private key to mine')
    else:
        reward_transaction = wallet.create_reward_transaction(wallet.address, COIN_REWARD_MAPPING[coin])

    blockchain.new_transaction(
        sender=reward_transaction.sender,
        recipient=reward_transaction.recipient,
        amount=reward_transaction.amount,
        signature=reward_transaction.signature,
        sender_wallet_address="Mining Reward",
        transaction_fee=reward_transaction.transaction_fee
    )

    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    return Success({
        'message': "New Block created! Congrats mf",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    })

@method
def pending_transactions():
    # Convert the Transaction objects to dictionaries
    blockchain.sort_pending_txn()

    transactions = [tx.to_dict() for tx in blockchain.current_transactions]
    
    return Success({
        'pending_txn': transactions,
        'length': len(transactions),
    })

@method
def full_chain():
    return Success({
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    })

# Drop Transaction from other nodes
@method
def remove_txn():
    try:
        blockchain.current_transactions = []
        return Success({'message': 'current_transactions has been emptied successfully'})
    except Exception as e:
        return Success({'message': f'An error occurred: {str(e)}'})
        
@method
def broadcast_node(node):
    success = blockchain.add_new_node(node)

    if success:
        return Success(f'New node added to the network.')
    else:
        return Error('InternalError', message='Failed to add new node.')
    
# POST - Broadcast Transaction Information to Peer Nodes
@method
def broadcast_transaction(sender, recipient, signature, amount, sender_wallet_address, transaction_fee):
    result = blockchain.add_transaction(sender, recipient, signature, amount, sender_wallet_address, transaction_fee, is_receiving=True)

    if result:
        transaction = blockchain.new_transaction(sender, recipient, amount, signature, sender_wallet_address, transaction_fee)
        
        blockchain.export_blockchain()
        return Success({'transaction': transaction.to_dict()})
    else:
        return Error('InternalError', message='Creating a transaction failed.')


@method
def broadcast_block(block):
    if block['index'] == blockchain.chain[-1]['index'] + 1:
        # If the block is the next expected block, add it to the local chain
        blockchain.chain.append(block)
        
        # Now broadcast this block to all peer nodes
        for node in blockchain.nodes:
            try:
                response = requests.post(f'http://{node}/broadcast_block', json={'block': block}, timeout=5)
                if response.status_code != 200 or 'error' in response.json():
                    print(f"Error broadcasting block to node {node}")
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                continue

        blockchain.export_blockchain()
        return Success('Block added and broadcasted')
    elif block['index'] > blockchain.chain[-1]['index']:
        # If the incoming block's index is greater, this could mean our local chain is behind.
        # Here, you can implement chain synchronization logic, like requesting the full chain 
        # from the node that sent you this block or asking multiple peers for their chains and 
        # deciding on the longest valid one. For simplicity, I'll just print a message.
        blockchain.export_blockchain()
        print("Local blockchain seems to be behind. Need to sync!")
        return Error('SyncRequired', message='Local blockchain seems to be behind. Need to sync!')
    else:
        blockchain.export_blockchain()
        print("Local blockchain seems to be behind. Need to sync!")
        return Error('InvalidRequest', message='Blockchain seems to be shorter, block not added')


@method
def get_wallet():
    # print(wallet.address)
    response = {
        'address': wallet.address,
        'private_key': wallet.private_key,
        'public_key': wallet.public_key,
        'balance': blockchain.get_balance(wallet.address),
    }
    return Success(response)

@method
def get_transactions_by_address(wallet_address):
    response = {
        'transactions': blockchain.get_transactions(wallet_address),
    }
    return Success(response)

@method
def get_balance_by_address(wallet_address):
    response = {
        'balance': blockchain.get_pending_balance(wallet_address),
    }
    return Success(response)

@method
def register_nodes(nodes):
    if nodes is None:
        return "Error: Please supply a valid list of nodes"

    # Send the current chain to the newly registered node
    for node in nodes:
        if not node.startswith('http://'):
            if node.startswith('https://'):
                # If 'https://' is present, return an error as HTTPS is not supported
                return Error('InternalError', message=f"Error: HTTPS protocol not supported for node URL '{node}'. Please use HTTP.")
            else:
                # If no protocol is present, prepend 'http://'
                node = 'http://' + node
                
        try:
            # Prepare JSON-RPC request
            request_json = {
                "jsonrpc": "2.0",
                "method": "sync_chain",
                "params": {"chain": blockchain.chain},
                "id": 1  # The request ID can be any integer
            }

            # Send JSON-RPC request
            response = requests.post(f"{node}/jsonrpc", json=request_json)
            if response.status_code != 200 or 'error' in response.json():
                return Error('InternalError', message=f"Error: Unable to sync chain with {node}")
            
            blockchain.register_node(node)
        except Exception as e:
            return Error('InternalError', message=f"Error: Unable to sync chain with {node} due to: {e}")

    return Success({
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    })



@method
def sync_chain(chain):
    if chain is None:
        return Error('InvalidParams', message='Please supply a valid chain')

    # Update the node's chain if the received chain is longer and valid
    if len(chain) > len(blockchain.chain) and blockchain.valid_chain(chain):
        blockchain.set_chain(chain)
        return Success("Chain updated")
    else:
        return Success("Chain not updated")


@method
def new_transaction(sender, private_key, recipient, amount, sender_wallet_address, transaction_fee):
    # Check that all parameters are not null or empty
    if not sender:
        return Error('InvalidParameter', message='Sender cannot be null or empty.')
    if not private_key:
        return Error('InvalidParameter', message='Private key cannot be null or empty.')
    if not recipient:
        return Error('InvalidParameter', message='Recipient cannot be null or empty.')
    if not sender_wallet_address:
        return Error('InvalidParameter', message='Sender wallet address cannot be null or empty.')
    if not transaction_fee:
        return Error('InvalidParameter', message='Transaction fee cannot be null or empty.')
        
   
    # signature = wallet.sign_transaction(wallet.public_key, recipient, amount)
    # success = blockchain.add_transaction(wallet.public_key, recipient, signature, amount, wallet.address)
    amount = float(amount)
    transaction_fee = float(transaction_fee)
    signature = wallet.sign_transaction(sender, private_key, recipient, amount)
    result = blockchain.add_transaction(sender, recipient, signature, amount, sender_wallet_address, transaction_fee)
    if not blockchain.nodes:
        return Error('InternalError', message='There are no nodes in your network')
    if result:
        return Success({
            'message': 'Successfully added transaction.',
            'transaction': result
        })
    else:
        return Error('InternalError', message='Creating a transaction failed.')

@method
def estimated_txn_fee():
    """
    Calculate the dynamic transaction fee based on the mempool transactions and their sizes.

    The estimation is determined using the following method:
    1. If the mempool is empty, return a base fee with varied priorities.
    2. If the mempool has transactions, the fees are calculated based on percentiles:
        - 25th percentile for low priority
        - 50th percentile (median) for medium priority
        - 75th percentile for high priority
    3. A congestion multiplier is applied which increases with the number of transactions 
       in the mempool to reflect network congestion.
    4. High and medium priority transactions have a percentage increase over the low priority 
       to ensure differentiation.

    :return: Dictionary with 'low_priority', 'medium_priority', and 'high_priority' fees.
    """
    mempool = blockchain.current_transactions
    BASE_FEE = 0.0001
    CONGESTION_MULTIPLIER = 0.00001 * len(mempool)  # dynamically increase the fee with more transactions

    if not mempool:
        return Success({
            'low_priority': format(BASE_FEE, '.6f'),
            'medium_priority': format(BASE_FEE * 2, '.6f'),
            'high_priority': format(BASE_FEE * 3, '.6f')
        })

    tx_sizes = [(tx, len(json.dumps(tx.to_dict()))) for tx in mempool]
    tx_fee_per_byte = [(tx, tx.to_dict()['transaction_fee'] / size) for tx, size in tx_sizes]

    fees = sorted([fee for _, fee in tx_fee_per_byte])

    # Directly using the percentiles for the fees
    low_priority_fee = BASE_FEE + fees[int(0.25 * len(fees))]  # 25th percentile
    medium_priority_fee = BASE_FEE + fees[int(0.5 * len(fees))]  # 50th percentile
    high_priority_fee = BASE_FEE + fees[int(0.75 * len(fees))]  # 75th percentile

    # Apply congestion multiplier
    low_priority_fee += CONGESTION_MULTIPLIER
    medium_priority_fee += 1.25 * CONGESTION_MULTIPLIER  # 25% more than low priority
    high_priority_fee += 1.5 * CONGESTION_MULTIPLIER  # 50% more than low priority

    response = {
        'low_priority': format(low_priority_fee, '.6f'),
        'medium_priority': format(medium_priority_fee, '.6f'),
        'high_priority': format(high_priority_fee, '.6f')
    }

    return Success(response)


@method
def get_nodes():
    response = {
        'nodes': list(blockchain.nodes),
    }
    return Success(response)

@method
def remove_nodes(node_li):
    blockchain.nodes = set(blockchain.nodes) - set(node_li)

    response = {
        'nodes': list(blockchain.nodes),
    }
    return Success(response)

@method
def check_node_health():
    response = {'status': 'OK'}
    return Success(response)

#________________________JSON-RPC________________________________#

@app.route('/jsonrpc', methods=['POST'])
def handle_jsonrpc():
    request_data = request.get_data().decode()
    response = dispatch(request_data)
    return Response(str(response), status=200, mimetype='application/json')

#________________________HELPER-FUNCTIONS________________________________#
def is_wallet_address(s):
    try:
        if len(s) > 50:
            int(s, 16)
            return True
        else:
            return False
    except ValueError:
        return False


def setup_port_forwarding(local_port, external_port, protocol='TCP'):
    # Discover UPnP devices on the network
    devices = upnpclient.discover()
    local_ip = blockchain.get_local_ip()

    is_success = False

    for device in devices:
        # Find the WANIPConnection service
        service = None
        for serv in device.services:
            if 'WANIPConnection' in serv.service_type:
                service = serv
                break
        if service:
            # Check for existing port mapping and delete if necessary
            try:
                existing_mapping = service.GetSpecificPortMappingEntry(NewRemoteHost='', NewExternalPort=external_port, NewProtocol=protocol)
                if existing_mapping:
                    service.DeletePortMapping(NewRemoteHost='', NewExternalPort=external_port, NewProtocol=protocol)
                    print(f"[*] Deleted existing port mapping on {device.friendly_name} for external port {external_port}")
            except Exception as e:
                # If the mapping doesn't exist, an error will be thrown. We can ignore it and proceed.
                pass

            # Add a new port mapping
            try:
                service.AddPortMapping(
                    NewRemoteHost='',
                    NewExternalPort=external_port,
                    NewProtocol=protocol,
                    NewInternalPort=local_port,
                    NewInternalClient=local_ip, 
                    NewEnabled='1',
                    NewPortMappingDescription=f'PortMapping for {local_port}->{external_port}',
                    NewLeaseDuration=0
                )
                is_success = True
                print(f"[*] Successfully added port mapping on {device.friendly_name} for external port {external_port} to local port {local_port}")
            except Exception as e:
                print(f"[*] Failed to add port mapping on {device.friendly_name}: {e}")

    if is_success == False:
        print("[*] Failed to use UPnP to auto setup port forwarding. Please configure manually in your router.")

def list_services():
    devices = upnpclient.discover()

    for device in devices:
        print(f"Device: {device.friendly_name}")
        for service in device.services:
            print(f"  Service: {service.service_type}")

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--coin', type=int, choices=[1, 2, 3, 4], help='Select the coin: 1 for FC, 2 for TKC, 3 for BTC, 4 for CTC')
    parser.add_argument('-f', '--file', type=str, help='File name for manual blockchain import')
    parser.add_argument('-m', '--manual', action='store_true', help='Disable automatic port forwarding')
    args = parser.parse_args()

    coin_select = args.coin
    if coin_select is None:
        print("Please specify a coin using the -c or --coin option.")
        sys.exit(1)

    if coin_select == 1:
        private_key = "4287ca3ba8e3dd84538b450c554b0ce5ae13db33cedb4340b637b6ad49ffc098"
    elif coin_select == 2:
        private_key = "e1b8ebaa4a9a29a800b8bb8378e6dcd82362121cd26aec789e6d6149fa8d047b"
    elif coin_select == 3:
        private_key = "7e83d27dba4b07b4ff98a2c22763f4e4fd2a462eef10117bcbc0e0a56ce38f42"
    elif coin_select == 4:
        private_key = "cf0c4abf0d88fc65bab333d9791fb0f6a554dd994f0c219fef0a4d2b04c326a0"

    COIN_PORT_MAPPING = {
        1: 5000,
        2: 5050,
        3: 6000,
        4: 6050,
    }

    if not is_wallet_address(private_key):
        print("Invalid wallet private key!")
        sys.exit(1)

    wallet = Wallet(private_key)
    port = COIN_PORT_MAPPING[coin_select]
    blockchain = Blockchain(port)

    if args.file:
        file_name = args.file
        with open(file_name, 'r') as file:
            blockchain.chain = json.load(file)

    BOOTSTRAP_NODES = [
        f'http://46.250.243.233:{port}',  # BC1
    ]

    for node in BOOTSTRAP_NODES:
        blockchain.register_node(node)

    public_ip = blockchain.get_public_ip()
    blockchain.add_new_node(f'http://{public_ip}:{port}')

    if not args.manual:
        print("[*] Auto Port Forwarding Setup.")
        setup_port_forwarding(port, port)
    else:
        print("[*] Manual Port Forwarding Setup.")

    app.run(host='0.0.0.0', port=port)

