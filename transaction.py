from datetime import datetime
import hashlib
import json
import pytz

class Transaction:
    def __init__(self, sender, recipient, amount, signature, sender_wallet_address, transaction_fee, referral_code=""):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature
        self.sender_wallet_address = sender_wallet_address
        self.transaction_fee = transaction_fee
        self.referral_code = referral_code

        # Get the current date and time in UTC and format it
        current_time_utc = datetime.now(pytz.utc)
        self.timestamp = current_time_utc.strftime('%d-%m-%Y %H:%M:%S %Z%z')

        # Generate transaction ID
        self.id = self.generate_txn_id()

    def to_dict(self, include_id=True):
        txn_dict = {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'signature': self.signature,
            'sender_wallet_address': self.sender_wallet_address,
            'timestamp': self.timestamp,
            'transaction_fee': self.transaction_fee,
            'referral_code': self.referral_code
        }
        if include_id:
            txn_dict['txId'] = self.id
        return txn_dict
    
    def generate_txn_id(self):
        # Exclude the ID when generating the hash
        txn_string = json.dumps(self.to_dict(include_id=False), sort_keys=True).encode()
        return hashlib.sha256(txn_string).hexdigest()
