from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
print (STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)
import csv
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CSV_PATH = DATA_DIR / "users.csv"
JSON_LOG_PATH = DATA_DIR / "log.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)

PERSONAL_SALT = "00012"
MIN_PASSWORD_LENGTH = 8


class ValidationError(Exception):  
    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Password or salt cannot be empty (None or '').")
    
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Password is too short! Minimum length: {MIN_PASSWORD_LENGTH} characters.")

    salted_password = password + salt
    return hashlib.md5(salted_password.encode('utf-8')).hexdigest()


def log_event(func):
    def wrapper(username: str, password: str, *args, **kwargs):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result_status = "failure"
        
        try:
            result = func(username, password, *args, **kwargs)
            if result:
                result_status = "success"
            return result
        except Exception as e:
            result_status = "failure"
            raise e
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": timestamp,
                "args": [username, "***"],  
                "kwargs": kwargs
            }
            
            logs = []
            if JSON_LOG_PATH.exists():
                try:
                    with open(JSON_LOG_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
            
            logs.append(log_entry)
            
            with open(JSON_LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)
                
    return wrapper


def create_user(username: str, password: str) -> tuple:
    hash_value = generate_hash(password, salt=PERSONAL_SALT)
    return (username, hash_value)


def create_users(users_list: list):
    with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["username", "password_hash"])
        
        for username, password in users_list:
            user_record = create_user(username, password)
            writer.writerow(user_record)
            
    print(f"\n[OK] Database successfully created/updated at the path:\n    {CSV_PATH}")


def read_database() -> list:
    users_db = []
    print(f"\n--- Contents of the structured CSV database ---")
    print(f"{'Username':<15} | {'MD5 Hash'}")
    print("-" * 50)
    
    with open(CSV_PATH, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            users_db.append(row)
            print(f"{row['username']:<15} | {row['password_hash']}")
            
    return users_db


@log_event
def login(username: str, password: str, users_db: list) -> bool:
    if not username or not password:
        raise ValueError("Login and password cannot be empty.")
    
    attempt_hash = generate_hash(password, salt=PERSONAL_SALT)
    
    for user_record in users_db:
        if user_record['username'] == username:
            return user_record['password_hash'] == attempt_hash
            
    return False


def main():
    print("    USER REGISTRATION ")
    users_to_register = []
    
    try:
        count = int(input("How many users do you want to register? "))
        
        for i in range(1, count + 1):
            print(f"\nUser #{i}:")
            u = input("  Enter username: ").strip()
            p = input("  Enter password (min. 8 characters): ").strip()
            users_to_register.append((u, p))

        create_users(users_to_register)
        
    except ValidationError as e:
        print(f"\n[Validation Error]: {e}")
        return
    except ValueError as e:
        print(f"\n[Input/Value Error]: {e}")
        return
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"\n[File System Error]: {e}")
        return

    try:
        users_db = read_database()
        print("\n   AUTHENTICATION (LOGIN) ")
        login_username = input("Enter username: ").strip()
        login_password = input("Enter password: ").strip()

        is_success = login(login_username, login_password, users_db)
        
        if is_success:
            print(f"\n[SUCCESS]: Login successful! Welcome, {login_username}.")
        else:
            print("\n[FAILURE]: Invalid username or password.")

    except ValueError as e:
        print(f"\n[Authentication Error]: {e}")
    except Exception as e:
        print(f"\n[Unexpected Error]: {e}")


if __name__ == "__main__":
    main()