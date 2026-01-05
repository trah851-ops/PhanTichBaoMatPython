import os
import pickle
import subprocess

def vulnerable_function(user_input):
    # SQL Injection
    query = "SELECT * FROM users WHERE id = " + user_input
    
    # Command Injection
    os.system("echo " + user_input)
    
    # Code Injection
    eval(user_input)
    exec(user_input)
    
    # Path Traversal
    file_path = "/data/" + user_input
    with open(file_path, 'r') as f:
        data = f.read()
    
    # Insecure Deserialization
    pickle.loads(user_input)
    
    # Hardcoded Password
    password = "admin123"
    api_key = "sk-1234567890abcdef"
    
    return query

def run_command(cmd):
    # Dangerous subprocess
    subprocess.call(cmd, shell=True)
    
if __name__ == "__main__":
    user_data = input("Enter data: ")
    vulnerable_function(user_data)