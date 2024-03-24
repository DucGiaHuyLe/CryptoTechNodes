import binascii
import hashlib
import json
from ecdsa import SigningKey, VerifyingKey, BadSignatureError, SECP256k1
from transaction import Transaction


class Wallet:
    def __init__(self, private_key=None):
        if private_key:
            self._private_key = SigningKey.from_string(binascii.unhexlify(private_key), curve=SECP256k1)
        else:
            self._private_key = SigningKey.generate(curve=SECP256k1)
        self._public_key = self._private_key.get_verifying_key()

    @property
    def address(self):
        public_key_bytes = self._public_key.to_string()
        address = hashlib.sha256(public_key_bytes).hexdigest()
        return address

    @property
    def private_key(self):
        return binascii.hexlify(self._private_key.to_string()).decode('utf-8')

    @property
    def public_key(self):
        return binascii.hexlify(self._public_key.to_string()).decode('utf-8')

    def sign_mining_transaction(self, transaction):
        transaction_data = json.dumps(transaction.to_dict(), sort_keys=True)
        signature = self._private_key.sign(transaction_data.encode())
        return binascii.hexlify(signature).decode('utf-8')
    
    def sign_mining_transaction_for_sommeone(self, transaction, private_key):
        transaction_data = json.dumps(transaction.to_dict(), sort_keys=True)
        private_key = self.str_to_private_key(private_key)
        signature = private_key.sign(transaction_data.encode())
        return binascii.hexlify(signature).decode('utf-8')

    def create_reward_transaction(self, miner_address, reward):
        transaction = Transaction(
            sender="0",
            recipient=miner_address,
            amount=reward,
            signature="0",
            sender_wallet_address="Mining Reward",
            transaction_fee=0
        )
        transaction.signature = self.sign_mining_transaction(transaction)
        return transaction
    
    def create_reward_transaction_for_sommeone(self, private_key, miner_address, reward):
        transaction = Transaction(
            sender="0",
            recipient=miner_address,
            amount=reward,
            signature="0",
            sender_wallet_address="Mining Reward",
            transaction_fee=0
        )
        transaction.signature = self.sign_mining_transaction_for_sommeone(transaction, private_key)
        return transaction
    
    def str_to_private_key(self, str_private_key):
        private_key_bytes = binascii.unhexlify(str_private_key)
        return SigningKey.from_string(private_key_bytes, curve=SECP256k1)

    # Please remember that when you create a signature, you use the private key and when you verify the signature, 
    # you use the corresponding public key. So, make sure you are using the right keys in your sign and verify functions. 
    # If the keys do not match, the verify_transaction function will return false.
    def sign_transaction(self, sender, private_key, recipient, amount):
        h = hashlib.sha256((str(sender) + str(recipient) + str(amount)).encode('utf8'))
        private_key = self.str_to_private_key(private_key)
        signature = private_key.sign(h.digest())
        return binascii.hexlify(signature).decode('ascii')

    
    # Verify signature of transaction
    def verify_transaction(self, transaction):
        h = hashlib.sha256((str(transaction.sender) + str(transaction.recipient) + str(transaction.amount)).encode('utf8'))
        try:
            public_key = VerifyingKey.from_string(binascii.unhexlify(transaction.sender), curve=SECP256k1)
            public_key.verify(binascii.unhexlify(transaction.signature), h.digest())
            return True
        except BadSignatureError:
            return False

