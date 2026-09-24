# Імпорт необхідних стандартних бібліотек Python
import csv 
import hashlib  
import json 
from datetime import datetime
from pathlib import Path

# мої дані
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)

# Визначаємо абсолютний шлях до директорії, де знаходиться цей скрипт
BASE_DIR = Path(__file__).resolve().parent
# Вказуємо шлях до папки 'data', де будуть зберігатися файли
DATA_DIR = BASE_DIR / "data"
# Шляхи до конкретних файлів бази даних та логів
CSV_PATH = DATA_DIR / "users.csv"       
JSON_LOG_PATH = DATA_DIR / "log.json"   

# Автоматичне створення папки 'data', якщо вона ще не існує
DATA_DIR.mkdir(parents=True, exist_ok=True)

PERSONAL_SALT = "00012"     
MIN_PASSWORD_LENGTH = 8     

# Створюємо власний клас винятку для помилок валідації паролів
class ValidationError(Exception):  
    pass

def generate_hash(password: str, salt: str = "00000") -> str:
    # Перевірка на порожній пароль або сіль
    if not password or not password.strip():
        raise ValueError("Password or salt cannot be empty.")
    if not salt or not salt.strip():
        raise ValueError("Password or salt cannot be empty.")
    
    # Перевірка на мінімальну довжину
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Password is too short! Minimum length: {MIN_PASSWORD_LENGTH} characters.")

    salted_password = password + salt
    return hashlib.md5(salted_password.encode('utf-8')).hexdigest()

def log_event(func):
    # Декоратор для автоматичного логування
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
                "user": username if username else "<EMPTY>",
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
    if not username or not username.strip():
        raise ValueError("Login cannot be empty.")
    if not password or not password.strip():
        raise ValueError("Password cannot be empty.")

    hash_value = generate_hash(password, salt=PERSONAL_SALT)
    return (username.strip(), hash_value)

def create_users(users_list: tuple):
    # Відкриваємо CSV-файл для запису
    with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["username", "password_hash"])
        
        # Перебираємо кожного користувача
        for username, password in users_list:
            try:
                user_record = create_user(username, password)
            except (ValueError, ValidationError):
                # Якщо дані некоректні чи порожні — формуємо запис з позначкою про помилку
                safe_username = username.strip() if username and username.strip() else "<EMPTY_USERNAME>"
                user_record = (safe_username, "<INVALID_PASSWORD>")
            
            writer.writerow(user_record)
            
    print(f"\n[OK] Database successfully created/updated at the path:\n    {CSV_PATH}")

def read_database() -> list:
    users_db = []
    print("\n--- Contents of the structured CSV database ---")
    print(f"{'Username':<15} | {'MD5 Hash / Status'}")
    print("-" * 50)
    
    with open(CSV_PATH, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            users_db.append(row)
            print(f"{row['username']:<15} | {row['password_hash']}")
            
    return users_db

@log_event
def login(username: str, password: str, users_db: list) -> bool:
    if not username or not username.strip() or not password or not password.strip():
        return False
    
    try:
        attempt_hash = generate_hash(password, salt=PERSONAL_SALT)
    except (ValueError, ValidationError):
        return False
    
    for user_record in users_db:
        if user_record['username'] == username.strip():
            return user_record['password_hash'] == attempt_hash
            
    return False

def main():
    print("    Реєстрація користувача ")
    
    # Кортеж із можливими порожніми чи некоректними записами для перевірки
    users_to_register = (
        ("admin", "SuperSecure1"),
        ("user1", "Password123"),
        ("guest", "GuestPass8"),
        ("marta", "MySecret12"),
        ("manager", "Manager123"),
        ("test_user", "TestPass8"),
        ("dev", "Developer8"),
        ("analyst", "Analyst123"),
        ("support", "Support123"),
        ("auditor", "AuditPass8"),
        
    )
    
    try:
        create_users(users_to_register)
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"\n[File System Error]: {e}")
        return

    try:
        # Зчитуємо та виводимо таблицю незалежно від наявності помилкових записів
        users_db = read_database() 
        
        print("\n   AUTHENTICATION (LOGIN) ")
        login_username = input("Enter username: ").strip()
        login_password = input("Enter password: ").strip()

        is_success = login(login_username, login_password, users_db)
        
        if is_success:
            print(f"\n[SUCCESS]: Login successful! Welcome, {login_username}.")
        else:
            print("\n[FAILURE]: Invalid username or password.")

    except Exception as e:
        print(f"\n[Unexpected Error]: {e}")

if __name__ == "__main__":
    main()