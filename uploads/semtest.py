import os
import subprocess
import json

# Vulnerable to Command Injection
def delete_user_data(username):
    os.system(f"rm -rf /home/{username}")

# Insecure Hardcoded Secret
SECRET_KEY = "12345"

# Insecure use of eval()
def calculate(expression):
    return eval(expression)

# SQL Injection Vulnerability
def get_user_info(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

# Potential Path Traversal
def read_file(filename):
    with open(f"/var/www/html/{filename}", "r") as file:
        return file.read()

# Deserialization Vulnerability
def deserialize_user_data(data):
    return json.loads(data)

# Insecure Use of Subprocess
def ping_host(host):
    subprocess.call(f"ping -c 4 {host}", shell=True)

# Main function
if __name__ == "__main__":
    username = input("Enter username to delete data: ")
    delete_user_data(username)

    expression = input("Enter a mathematical expression: ")
    print("Result:", calculate(expression))

    user_id = input("Enter user ID to fetch info: ")
    print(get_user_info(user_id))

    filename = input("Enter filename to read: ")
    print(read_file(filename))

    host = input("Enter host to ping: ")
    ping_host(host)
