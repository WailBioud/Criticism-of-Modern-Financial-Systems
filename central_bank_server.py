import socket
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import time
from dataclasses import dataclass, asdict
from enum import Enum, auto

class TransactionStatus(Enum):
    COMPLETED = auto()
    REJECTED = auto()
    FLAGGED = auto()

@dataclass
class Transaction:
    id: str
    sender: str
    receiver: str
    amount: float
    timestamp: float
    status: TransactionStatus
    signature: str = ""

class CentralBankServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.accounts = {}
        self.transactions = []
        self.total_money_supply = 10_000_000
        self.used_money = 0
        self.server_key = RSA.generate(2048)
        self.client_keys = {}
        
        # Load server config
        self.load_config()
        
        # Setup server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        
    def load_config(self):
        """تحميل إعدادات السيرفر من ملف"""
        try:
            with open('server/config.json') as f:
                config = json.load(f)
                self.transaction_limit = config.get('transaction_limit', 10000)
                self.admin_password = config.get('admin_password', 'admin123')
        except:
            self.transaction_limit = 10000
            self.admin_password = 'admin123'

    def start(self):
        """بدء تشغيل السيرفر"""
        print(f"🚀 Starting Central Bank Server on {self.host}:{self.port}")
        self.server_socket.listen(5)
        
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"🔗 New connection from {addr}")
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, addr)
            )
            client_thread.start()

    def handle_client(self, client_socket, addr):
        """معالجة اتصال العميل"""
        try:
            # إرسال المفتاح العام للعميل
            public_key = self.server_key.publickey().export_key()
            client_socket.send(public_key)
            
            # استقبال المفتاح العام من العميل
            client_public_key = RSA.import_key(client_socket.recv(2048))
            self.client_keys[addr] = client_public_key
            
            while True:
                encrypted_data = client_socket.recv(2048)
                if not encrypted_data:
                    break
                    
                # فك التشفير
                cipher = PKCS1_OAEP.new(self.server_key)
                decrypted_data = cipher.decrypt(encrypted_data)
                request = json.loads(decrypted_data.decode())
                
                # معالجة الطلب
                response = self.process_request(request, addr)
                
                # تشفير وتوجيه الاستجابة
                response_data = json.dumps(response).encode()
                cipher = PKCS1_OAEP.new(client_public_key)
                encrypted_response = cipher.encrypt(response_data)
                client_socket.send(encrypted_response)
                
        except Exception as e:
            print(f"⚠️ Error with {addr}: {e}")
        finally:
            client_socket.close()
            if addr in self.client_keys:
                del self.client_keys[addr]
            print(f"❌ Connection closed with {addr}")

    def process_request(self, request, addr):
        """معالجة طلبات العميل"""
        action = request.get('action')
        client_id = request.get('client_id')
        password = request.get('password', '')
        amount = request.get('amount', 0)
        receiver = request.get('receiver', '')
        
        # التحقق من التوثيق
        if not self.authenticate(client_id, password):
            return {'status': 'error', 'message': 'Authentication failed'}
            
        if action == 'create_account':
            if client_id in self.accounts:
                return {'status': 'error', 'message': 'Account already exists'}
            self.accounts[client_id] = amount
            self.used_money += amount
            return {'status': 'success', 'balance': self.accounts[client_id]}
            
        elif action == 'get_balance':
            if client_id not in self.accounts:
                return {'status': 'error', 'message': 'Account not found'}
            return {'status': 'success', 'balance': self.accounts[client_id]}
            
        elif action == 'transfer':
            if client_id not in self.accounts or receiver not in self.accounts:
                return {'status': 'error', 'message': 'Invalid account'}
                
            if self.accounts[client_id] < amount:
                return {'status': 'error', 'message': 'Insufficient funds'}
                
            if amount > self.transaction_limit:
                tx_id = f"tx_{time.time()}"
                transaction = Transaction(
                    id=tx_id,
                    sender=client_id,
                    receiver=receiver,
                    amount=amount,
                    timestamp=time.time(),
                    status=TransactionStatus.FLAGGED,
                    signature=self.sign_transaction(client_id, receiver, amount)
                )
                self.transactions.append(transaction)
                return {
                    'status': 'flagged',
                    'message': 'Transaction exceeds limit',
                    'tx_id': tx_id
                }
                
            # تنفيذ التحويل
            self.accounts[client_id] -= amount
            self.accounts[receiver] += amount
            
            tx_id = f"tx_{time.time()}"
            transaction = Transaction(
                id=tx_id,
                sender=client_id,
                receiver=receiver,
                amount=amount,
                timestamp=time.time(),
                status=TransactionStatus.COMPLETED,
                signature=self.sign_transaction(client_id, receiver, amount)
            )
            self.transactions.append(transaction)
            
            return {
                'status': 'success',
                'balance': self.accounts[client_id],
                'tx_id': tx_id
            }
            
        return {'status': 'error', 'message': 'Invalid action'}

    def authenticate(self, client_id, password):
        """توثيق العميل (محاكاة)"""
        # في نظام حقيقي، يجب استخدام قاعدة بيانات وآليات توثيق آمنة
        return True  # مؤقتاً للاختبار

    def sign_transaction(self, sender, receiver, amount):
        """توقيع المعاملة رقمياً"""
        data = f"{sender}{receiver}{amount}{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()

if __name__ == "__main__":
    server = CentralBankServer()
    server.start()
