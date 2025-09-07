import bcrypt
import json
import os

USER_FILE = "users.json"

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

def create_user(username, password):
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users = load_users()
    users[username] = hashed_pw
    save_users(users)
    print(f"User '{username}' added.")

# Example
if __name__ == "__main__":
    create_user("admin", "admin123")
