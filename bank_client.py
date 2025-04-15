import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import getpass
import hashlib

class BankClient:
    def __init__(self, server_host='localhost', server_port=5555):
        self.server_host = server_host
        self.server_port = server_port
        self.client_key = RSA.generate(2048)
        self.session_key = None
        self.client_id = None
        self.password = None
        
    def connect(self):
        """الاتصال بالسيرفر"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((self.server_host, self.server_port))
            
            # استقبال المفتاح العام من السيرفر
            server_public_key = RSA.import_key(self.socket.recv(2048))
            self.server_cipher = PKCS1_OAEP.new(server_public_key)
            
            # إرسال المفتاح العام للعميل
            self.socket.send(self.client_key.publickey().export_key())
            self.client_cipher = PKCS1_OAEP.new(self.client_key)
            
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False
            
    def send_request(self, request):
        """إرسال طلب مشفر للسيرفر"""
        try:
            encrypted = self.server_cipher.encrypt(json.dumps(request).encode())
            self.socket.send(encrypted)
            
            response = self.socket.recv(2048)
            if not response:
                return None
                
            decrypted = self.client_cipher.decrypt(response)
            return json.loads(decrypted.decode())
        except Exception as e:
            print(f"Communication error: {e}")
            return None
            
    def login(self):
        """تسجيل دخول العميل"""
        self.client_id = input("Enter client ID: ")
        self.password = getpass.getpass("Enter password: ")
        
    def create_account(self, initial_balance=0):
        """إنشاء حساب جديد"""
        request = {
            'action': 'create_account',
            'client_id': self.client_id,
            'password': self.password,
            'amount': initial_balance
        }
        return self.send_request(request)
        
    def get_balance(self):
        """الحصول على الرصيد"""
        request = {
            'action': 'get_balance',
            'client_id': self.client_id,
            'password': self.password
        }
        return self.send_request(request)
        
    def transfer(self, receiver, amount):
        """تحويل الأموال"""
        request = {
            'action': 'transfer',
            'client_id': self.client_id,
            'password': self.password,
            'receiver': receiver,
            'amount': amount
        }
        return self.send_request(request)
        
    def close(self):
        """إغلاق الاتصال"""
        self.socket.close()

def main():
    print("Central Bank Client - Secure Banking System")
    print("=========================================\n")
    
    client = BankClient()
    if not client.connect():
        print("Failed to connect to server")
        return
        
    client.login()
    
    while True:
        print("\nMenu:")
        print("1. Create Account")
        print("2. Check Balance")
        print("3. Transfer Money")
        print("4. Exit")
        
        choice = input("Select option: ")
        
        if choice == '1':
            balance = float(input("Initial balance: "))
            response = client.create_account(balance)
            print(response)
            
        elif choice == '2':
            response = client.get_balance()
            if response and response['status'] == 'success':
                print(f"Your balance: {response['balance']}")
            else:
                print("Error:", response.get('message', 'Unknown error'))
                
        elif choice == '3':
            receiver = input("Receiver ID: ")
            amount = float(input("Amount: "))
            response = client.transfer(receiver, amount)
            
            if response:
                if response['status'] == 'flagged':
                    print("⚠️ Transaction flagged for review")
                    print("Transaction ID:", response['tx_id'])
                elif response['status'] == 'success':
                    print("✅ Transfer successful")
                    print("New balance:", response['balance'])
                    print("Transaction ID:", response['tx_id'])
                else:
                    print("❌ Error:", response.get('message', 'Unknown error'))
                    
        elif choice == '4':
            break
            
    client.close()
    print("Goodbye!")

if __name__ == "__main__":
    main()
