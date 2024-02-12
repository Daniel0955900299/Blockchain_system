# Python==3.11.5
# Flask==3.0.0

import datetime
import hashlib
import json
import requests
from dataclasses import dataclass, asdict, field
from flask import Flask, jsonify, request
from uuid import uuid4
from urllib.parse import urlparse

@dataclass
class Block:
    index: int
    timestamp: str
    proof: int
    previous_hash: str
    transactions: list = field(default_factory=list)

@dataclass
class Transaction:
    sender: str
    receiver: str
    amount: int

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.nodes = set()
        self.create_initial_block()

    def create_initial_block(self):
        self.chain.append(Block(1, str(datetime.datetime.now()), 1, '0'))

    def add_block(self, proof, previous_hash):
        block = Block(len(self.chain) + 1, str(datetime.datetime.now()), proof, previous_hash, self.pending_transactions.copy())
        self.pending_transactions = []
        self.chain.append(block)
        return block

    def add_transaction(self, sender, receiver, amount):
        transaction = Transaction(sender, receiver, amount)
        self.pending_transactions.append(transaction)
        return self.get_recent_block().index + 1

    def get_recent_block(self):
        return self.chain[-1]

    @staticmethod
    def hash_block(block):
        encoded_block = json.dumps(asdict(block), sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def proof_of_work(self, last_proof):
        proof = 1
        while not self.is_proof_valid(proof, last_proof):
            proof += 1
        return proof

    @staticmethod
    def is_proof_valid(proof, last_proof):
        guess = f'{proof}-{last_proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:5] == "00000"

    def is_chain_valid(self, chain=None):
        if chain is None:
            chain = self.chain
        if len(chain) == 0:
            return True
        for i in range(1, len(chain)):
            block = chain[i]
            previous_block = chain[i - 1]
            if block.previous_hash != self.hash_block(previous_block):
                return False
            if not self.is_proof_valid(block.proof, previous_block.proof):
                return False
        return True

    def register_node(self, address):
        self.nodes.add(urlparse(address).netloc)

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None
        current_length = len(self.chain)

        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > current_length and self.is_chain_valid(chain):
                    current_length = length
                    new_chain = chain

        if new_chain:
            self.chain = [Block(**block) for block in new_chain]
            return True

        return False

app = Flask(__name__)
blockchain = Blockchain()
node_identifier = str(uuid4()).replace('-', '')

@app.route('/mine', methods=['GET'])
def mine_block():
    last_block = blockchain.get_recent_block()
    proof = blockchain.proof_of_work(last_block.proof)
    blockchain.add_transaction("Paweł", node_identifier, 1)
    previous_hash = Blockchain.hash_block(last_block)
    block = blockchain.add_block(proof, previous_hash)

    response = {
        'message': 'Nowy block zostal pomyslnie utworzony',
        'block': asdict(block)
    }
    return jsonify(response), 200

@app.route('/add_transaction', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'receiver', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    index = blockchain.add_transaction(values['sender'], values['receiver'], values['amount'])
    response = {'message': f'Transakcja zostanie dodana do bloku {index}'}
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
def get_blockchain():
    response = {
        'chain': [asdict(block) for block in blockchain.chain],
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200

@app.route('/connect_node', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'Wszystkie wezli są teraz połączone. Blockchain Gencoin zawira teraz następujące węzly:',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/replace_chain', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    message = 'Our chain was replaced' if replaced else 'Our chain is authoritative'
    response = {'message': message, 'chain': [asdict(block) for block in blockchain.chain]}
    return jsonify(response), 200



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)