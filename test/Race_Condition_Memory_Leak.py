import threading

balance = 1000
lock = None  # Missing lock!

def withdraw(amount):
    global balance
    # Race condition - no lock
    if balance >= amount:
        balance -= amount
    return balance

def read_file_unsafe(filename):
    # Memory leak - no close
    f = open(filename, 'r')
    data = f.read()
    # Forgot f.close()
    return data

def process_data():
    # Resource leak
    connection = database.connect()
    result = connection.query("SELECT *")
    # Forgot connection.close()
    return result