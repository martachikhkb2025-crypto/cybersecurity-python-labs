#мої дані
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)

# Імпорт необхідних стандартних бібліотек Python
import csv          
import hashlib     
import json         
import os
from datetime import datetime  
from pathlib import Path      

# Визначаємо абсолютний шлях до директорії, де знаходиться цей скрипт
BASE_DIR = Path(__file__).resolve().parent
# Вказуємо шлях до папки 'data', де будуть зберігатися файли
DATA_DIR = BASE_DIR / "data"
# Шляхи до конкретних файлів бази даних та логів
CSV_PATH = DATA_DIR / "users.csv"       
JSON_LOG_PATH = DATA_DIR / "log.json"   

# Автоматичне створення папки 'data', якщо вона ще не існує. 
# parents=True дозволяє створювати вкладені папки, 
# exist_ok=True ігнорує помилку, якщо папка вже є.
DATA_DIR.mkdir(parents=True, exist_ok=True)

PERSONAL_SALT = "00012"     
MIN_PASSWORD_LENGTH = 8     

# Створюємо власний клас винятку для помилок валідації паролів(успадковується від базового класу Exception)
class ValidationError(Exception):  
    pass

def generate_hash(password: str, salt: str = "00000") -> str:
    #Функція для генерації безпечного хешу пароля з використанням солі.
    # Перевірка, чи не передано порожній пароль або сіль
    if not password or not salt:
        raise ValueError("Password or salt cannot be empty (None or '').")
    
    # Перевірка надійності: чи відповідає пароль мінімальній довжині
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Password is too short! Minimum length: {MIN_PASSWORD_LENGTH} characters.")

    #Об'єднання пароля та солі для захисту від райдужних таблиць
    salted_password = password + salt

    # Використовуємо MD5 , .encode('utf-8') перетворює рядок на байти, а .hexdigest() повертає результат у зручному шістнадцятковому форматі.
    return hashlib.md5(salted_password.encode('utf-8')).hexdigest()

def log_event(func):
    # Декоратор для автоматичного логування кожної спроби виклику функції авторизації (login)
    def wrapper(username: str, password: str, *args, **kwargs):
        # Фіксуємо поточний час
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result_status = "failure" # Початковий статус - невдача
        
        try:
            # Викликаємо оригінальну функцію (login) і зберігаємо її результат
            result = func(username, password, *args, **kwargs)
            if result:
                result_status = "success" 
            return result
        except Exception as e:
            result_status = "failure"
            raise e # Прокидаємо помилку далі, щоб її обробив блок try-except у main()
        finally:  # Блок finally виконується ЗАВЖДИ, незалежно від того, була помилка чи ні.
            # Формуємо словник із записом для журналу логів
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": timestamp,
                "args": [username, "***"],  
                "kwargs": kwargs
            }
            
            logs = []
            # Якщо файл журналу вже існує, зчитуємо його попередній вміст
            if JSON_LOG_PATH.exists():
                try:
                    with open(JSON_LOG_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except json.JSONDecodeError:
                    logs = [] # Якщо файл пошкоджений або порожній, починаємо новий список
            
            # Додаємо новий запис про спробу входу до списку
            logs.append(log_entry)
            
            # Перезаписуємо файл JSON з новим записом, використовуючи відступи (indent) для читабельності
            with open(JSON_LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)
                
    return wrapper

def create_user(username: str, password: str) -> tuple:
#Генерує хеш для пароля та повертає кортеж (логін, хеш)
    hash_value = generate_hash(password, salt=PERSONAL_SALT)
    return (username, hash_value)

def create_users(users_list: tuple):       #Приймає кортеж користувачів, хешує їхні паролі та записує їх у CSV-файл
 # Відкриваємо CSV-файл для запису. Режим "w" перезаписує існуючий файл.
    with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["username", "password_hash"])
        
        # Перебираємо кожного користувача у переданому кортежі
        for username, password in users_list:
            user_record = create_user(username, password)
            writer.writerow(user_record) # Записуємо кортеж у вигляді нового рядка CSV
            
    print(f"\n[OK] Database successfully created/updated at the path:\n    {CSV_PATH}")

def read_database() -> list:    #Зчитує дані користувачів з CSV-файлу та виводить їх у вигляді таблиці на екран.
    users_db = []
    print(f"\n--- Contents of the structured CSV database ---")
    print(f"{'Username':<15} | {'MD5 Hash'}")
    print("-" * 50)
    
    # Відкриваємо файл для читання, DictReader дозволяє звертатись до колонок за їхніми назвами.
    with open(CSV_PATH, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            users_db.append(row)
            print(f"{row['username']:<15} | {row['password_hash']}")   #вирівнювання по лівому краю
            
    return users_db

@log_event    # Декоратор автоматично "обгорне" цю функцію і запише лог при кожному виклику
def login(username: str, password: str, users_db: list) -> bool:    #Перевіряє, чи існує користувач у базі та чи правильний пароль.
    if not username or not password:
        raise ValueError("Login and password cannot be empty.")
    
    # Хешуємо пароль, який ввів користувач при спробі входу, з тією ж самою сіллю
    attempt_hash = generate_hash(password, salt=PERSONAL_SALT)
    
    # Шукаємо користувача у базі
    for user_record in users_db:
        if user_record['username'] == username:
            # Якщо знайшли, порівнюємо хеш із бази з хешем щойно введеного пароля
            return user_record['password_hash'] == attempt_hash
            
    # Якщо користувача не знайдено або цикл завершився без збігів
    return False

def main():
    print("    Реєстрація користувача ")
    
    # Фіксований кортеж з 10 записів (користувачів)
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
        ("auditor", "AuditPass8")
    )
    
    try:                # Блок обробки винятків для безпечного створення бази даних
        # Відправляємо кортеж користувачів на реєстрацію і запис у CSV
        create_users(users_to_register)
        
    except ValidationError as e:           
         # Перехоплюємо нашу кастомну помилку (наприклад, надто короткий пароль)
        print(f"\n[Validation Error]: {e}")
        return
    except ValueError as e:
        # Перехоплюємо помилки значень (наприклад, порожній пароль)
        print(f"\n[Input/Value Error]: {e}")
        return
    except (FileNotFoundError, PermissionError, IOError) as e:
        # Перехоплюємо системні помилки роботи з файлами (немає доступу тощо)
        print(f"\n[File System Error]: {e}")
        return

    try:           # Блок обробки винятків для безпечної автентифікації
        # Зчитуємо щойно створену базу даних у список словників
        users_db = read_database() 
        
        # Тестування авторизації через інтерактивне введення
        print("\n   AUTHENTICATION (LOGIN) ")
        login_username = input("Enter username: ").strip()
        login_password = input("Enter password: ").strip()

        # Виклик функції авторизації
        is_success = login(login_username, login_password, users_db)
        
        # Виведення результату на екран
        if is_success:
            print(f"\n[SUCCESS]: Login successful! Welcome, {login_username}.")
        else:
            print("\n[FAILURE]: Invalid username or password.")

    except ValueError as e:
        print(f"\n[Authentication Error]: {e}")
    except Exception as e:
        # Глобальний перехоплювач для непередбачуваних помилок, щоб програма не "впала"
        print(f"\n[Unexpected Error]: {e}")

if __name__ == "__main__":
    main()