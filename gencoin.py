import datetime  # Импорт модуля для работы с датами и временем
import hashlib  # Импорт модуля для хеширования данных
import json  # Импорт модуля для работы с JSON форматом
import requests  # Импорт модуля для отправки HTTP запросов
from dataclasses import dataclass, asdict, field  # Импорт для создания классов данных
from flask import Flask, jsonify, request  # Импорт Flask и необходимых функций для создания API
from uuid import uuid4  # Импорт функции для генерации уникальных идентификаторов
from urllib.parse import urlparse  # Импорт функции для парсинга URL

@dataclass
class Block:
    # Класс представляет собой блок в блокчейне
    index: int  # Индекс блока в цепочке
    timestamp: str  # Временная метка создания блока
    proof: int  # Доказательство выполненной работы
    previous_hash: str  # Хеш предыдущего блока в цепочке
    transactions: list = field(default_factory=list)  # Список транзакций в блоке

@dataclass
class Transaction:
    # Класс представляет собой транзакцию
    sender: str  # Отправитель транзакции
    receiver: str  # Получатель транзакции
    amount: int  # Сумма транзакции

class Blockchain:
    def __init__(self):
        self.chain = []  # Список блоков в блокчейне
        self.pending_transactions = []  # Список ожидающих транзакций
        self.nodes = set()  # Множество узлов в сети блокчейна
        self.create_initial_block()  # Создание начального блока

    def create_initial_block(self):
        # Создание начального блока (genesis block) и добавление его в цепочку
        self.chain.append(Block(1, str(datetime.datetime.now()), 1, '0'))

    def add_block(self, proof, previous_hash):
        # Добавление нового блока к цепочке
        block = Block(len(self.chain) + 1, str(datetime.datetime.now()), proof, previous_hash, self.pending_transactions.copy())
        self.pending_transactions = []  # Очистка списка ожидающих транзакций
        self.chain.append(block)
        return block

    def add_transaction(self, sender, receiver, amount):
        # Добавление транзакции в список ожидающих
        transaction = Transaction(sender, receiver, amount)
        self.pending_transactions.append(transaction)
        return self.get_recent_block().index + 1  # Возврат индекса блока, к которому будет добавлена транзакция

    def get_recent_block(self):
        # Получение последнего блока в цепочке
        return self.chain[-1]

    @staticmethod
    def hash_block(block):
        # Вычисление хеша блока
        encoded_block = json.dumps(asdict(block), sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def proof_of_work(self, last_proof):
        # Алгоритм доказательства выполнения работы (Proof of Work)
        proof = 1
        while not self.is_proof_valid(proof, last_proof):
            proof += 1
        return proof

    @staticmethod
    def is_proof_valid(proof, last_proof):
        # Проверка валидности доказательства работы
        guess = f'{proof}-{last_proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:5] == "00000"

    def is_chain_valid(self, chain=None):
        # Проверка валидности всей цепочки блоков
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
        # Регистрация нового узла в сети блокчейна
        self.nodes.add(urlparse(address).netloc)

    def resolve_conflicts(self):
        # Алгоритм консенсуса для разрешения конфликтов между цепочками блоков
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

# Создание Flask приложения и определение endpoint'ов для работы с блокчейном
app = Flask(__name__)
blockchain = Blockchain()
node_identifier = str(uuid4()).replace('-', '')  # Генерация уникального идентификатора для узла


@app.route('/mine', methods=['GET'])
def mine_block():
    # Endpoint do "wydobywania" nowego bloku
    last_block = blockchain.get_recent_block()
    proof = blockchain.proof_of_work(last_block.proof)
    blockchain.add_transaction("Daniel", node_identifier, 1)  # Nagroda za wydobycie bloku
    previous_hash = Blockchain.hash_block(last_block)
    block = blockchain.add_block(proof, previous_hash)

    response = {
        'message': 'Nowy block zostal pomyslnie utworzony',
        'block': asdict(block)
    }
    return jsonify(response), 200

@app.route('/add_transaction', methods=['POST'])
def new_transaction():
    # Endpoint do dodawania nowej transakcji
    values = request.get_json()
    required = ['sender', 'receiver', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    index = blockchain.add_transaction(values['sender'], values['receiver'], values['amount'])
    response = {'message': f'Transakcja zostanie dodana do bloku {index}'}
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
def get_blockchain():
    # Endpoint do uzyskania bieżącego łańcucha bloków
    response = {
        'chain': [asdict(block) for block in blockchain.chain],
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200

@app.route('/connect_node', methods=['POST'])
def register_nodes():
    # Endpoint do rejestracji nowych węzłów
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
    # Endpoint do sprawdzenia i ewentualnej zmiany łańcucha na dłuższy
    replaced = blockchain.resolve_conflicts()
    message = 'Our chain was replaced' if replaced else 'Our chain is authoritative'
    response = {'message': message, 'chain': [asdict(block) for block in blockchain.chain]}
    return jsonify(response), 200

@app.route('/valid', methods=['GET'])
def check_validity():
    # Endpoint do sprawdzenia ważności blockchaina
    is_valid = blockchain.is_chain_valid()
    message = 'Valid.' if is_valid else 'Not Valid'
    return jsonify({'message': message}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
