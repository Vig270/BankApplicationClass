import base64
import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class NewBankAppSpring2024:
    def __init__(self):
        self.secret_key = b'ThisIsASecretKey'  # Initialize secret key
        self.customer_name = None
        self.customer_id = None
        self.balance = 0  # Initialize balance to zero at the start of each session

    def get_user_info(self):
        self.customer_name = input("Enter your name (max 8 characters): ")[:8]
        self.customer_id = input("Enter your ID (max 8 characters): ")[:8]
        self.encrypted_name, self.encrypted_id = self.encrypt_data(self.customer_name, self.customer_id)

        # Write encoded secret key and encrypted data to files
        with open("secret_key.txt", "wb") as f:
            f.write(base64.b64encode(self.secret_key))
        with open("encrypted_name.txt", "wb") as f:
            f.write(base64.b64encode(self.encrypted_name))
        with open("encrypted_id.txt", "wb") as f:
            f.write(base64.b64encode(self.encrypted_id))

    def encrypt_data(self, name, id):
        iv = get_random_bytes(16)
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        encrypted_name = cipher.encrypt(name.ljust(16).encode())
        encrypted_id = cipher.encrypt(id.ljust(16).encode())
        return encrypted_name, encrypted_id

    def decrypt_data(self, encrypted_data):
        iv = encrypted_data[:16]
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data[16:])
        return decrypted_data.strip().decode()

    def deposit(self, amount):
        if amount <= 0:
            print("Invalid deposit amount. Please reenter a value.")
            return
        if amount > 500:
            raise DailyLimitException("Daily deposit limit exceeded. Maximum deposit amount is 500.")
        self.balance += amount
        self.previous_transaction = amount
        self.audit_transaction("Deposit", amount)

    def withdraw(self, amount):
        if amount <= 0:
            print("Error, invalid withdrawal amount. Please enter a valid amount.")
            return
        if amount > self.balance:
            print("Error, insufficient funds. Cannot withdraw more than available balance.")
            return
        self.balance -= amount
        self.previous_transaction = -amount
        self.balance -= 1  # Charge a small fee
        self.audit_transaction("Withdrawal", amount)

    def get_previous_transaction(self):
        if self.previous_transaction > 0:
            print("Deposited:", self.previous_transaction)
        elif self.previous_transaction < 0:
            print("Withdrawn:", abs(self.previous_transaction))
        else:
            print("No transaction history.")

    def show_menu(self):
        self.balance = 0  # Initialize balance to zero at the start of each session
        while True:
            print("A - Check Balance")
            print("B - Deposit")
            print("C - Withdraw")
            print("D - Transaction History")
            print("E - Exit")
            option = input("Enter an option: ").upper()
            print()
            if option == 'A':
                print("Your balance is: $", self.balance)
            elif option == 'B':
                amount = int(input("Enter amount to deposit: "))
                self.deposit(amount)
                print("Your balance after deposit is: $", self.balance)
            elif option == 'C':
                amount = int(input("Enter amount to withdraw: "))
                self.withdraw(amount)
                print("Your balance after withdrawal is: $", self.balance)
            elif option == 'D':
                self.get_previous_transaction()
            elif option == 'E':
                print("Exiting the application...")
                break
            else:
                print("Invalid option. Only A, B, C, D, or E is available")

        query_before_encoding = "<#BankersULT.gif>"
        print("Here is our URL before encoding: https://Group1bank.com?query=" + query_before_encoding)
        print("Here is our URL after encoding:", self.build_encoded_url(query_before_encoding))
        print("Thank you. Have a nice day!")

    @staticmethod
    def build_encoded_url(q):
        encoded_url = "https://Group1bank.com?query==" + base64.urlsafe_b64encode(q.encode()).decode()
        return encoded_url

    def audit_transaction(self, transaction_type, amount):
        with open("transaction_log.txt", "a") as f:
            date = datetime.datetime.now()
            f.write(f"Date: {date}, Customer ID: {self.customer_id}, Transaction Type: {transaction_type}, Amount: {amount}\n")

class DailyLimitException(Exception):
    pass

if __name__ == "__main__":
    banking_app = NewBankAppSpring2024()
    banking_app.get_user_info()
    banking_app.show_menu()
