# Підтягуємо мої дані (ПІБ, група, варіант), щоб було зрозуміло, чия це робота
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)

# Імпортуємо всі необхідні бібліотеки: для роботи з файлами, хешування, форматування часу тощо
import csv
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

# Визначаємо шляхи до файлів. Використовуємо pathlib, щоб шляхи працювали 
# і на Windows, і на Mac/Linux без проблем зі слешами
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CSV_PATH = DATA_DIR / "users.csv"       # Тут буде наша "база даних"
JSON_LOG_PATH = DATA_DIR / "log.json"   # А тут логуватимемо спроби входу

# Якщо папки data ще немає, створюємо її (exist_ok=True означає, що помилки не буде, якщо вона вже є)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Моя унікальна "сіль" для хешування та вимога до довжини пароля
PERSONAL_SALT = "00012"
MIN_PASSWORD_LENGTH = 8

# Створюємо власний клас помилки для валідації паролів
class ValidationError(Exception):  
    pass

# Функція для хешування. Ніколи не зберігаємо паролі в чистому вигляді!
def generate_hash(password: str, salt: str = "00000") -> str:
    # Захист від дурня: пароль і сіль не можуть бути порожніми
    if not password or not salt:
        raise ValueError("Password or salt cannot be empty (None or '').")
    
    # Перевіряємо, чи пароль не надто короткий
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Password is too short! Minimum length: {MIN_PASSWORD_LENGTH} characters.")

    # Додаємо "сіль" до пароля, щоб ускладнити злам (захист від райдужних таблиць)
    salted_password = password + salt
    # Використовуємо MD5 для хешування і повертаємо результат у вигляді рядка
    return hashlib.md5(salted_password.encode('utf-8')).hexdigest()

# Це декоратор! Він буде непомітно "обгортати" нашу функцію login і логувати всі події
def log_event(func):
    def wrapper(username: str, password: str, *args, **kwargs):
        # Фіксуємо час спроби входу
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result_status = "failure" # За замовчуванням вважаємо, що вхід не вдався
        
        try:
            # Викликаємо саму функцію login
            result = func(username, password, *args, **kwargs)
            if result:
                result_status = "success" # Якщо функція повернула True — вхід успішний
            return result
        except Exception as e:
            result_status = "failure"
            raise e
        finally:
            # Цей блок виконається в будь-якому випадку. Формуємо запис для логу
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": timestamp,
                # ЗВЕРНІТЬ УВАГУ: я спеціально ховаю пароль під зірочками, 
                # щоб він не світився у лог-файлі! Це важливо для безпеки.
                "args": [username, "***"],  
                "kwargs": kwargs
            }
            
            logs = []
            # Якщо файл з логами вже існує, спочатку читаємо старі записи
            if JSON_LOG_PATH.exists():
                try:
                    with open(JSON_LOG_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except json.JSONDecodeError:
                    logs = [] # Якщо файл пошкоджений або порожній, починаємо з чистого аркуша
            
            # Додаємо нову спробу
            logs.append(log_entry)
            
            # І записуємо все назад у JSON-файл із гарним форматуванням (indent=4)
            with open(JSON_LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)
                
    return wrapper

# Функція просто бере юзера і пароль, і повертає юзера разом з його хешем
def create_user(username: str, password: str) -> tuple:
    hash_value = generate_hash(password, salt=PERSONAL_SALT)
    return (username, hash_value)

# Функція для запису списку нових користувачів у CSV-файл
def create_users(users_list: list):
    # Відкриваємо файл на запис (режим 'w' перезапише файл, якщо він був)
    with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        # Спочатку пишемо заголовки колонок
        writer.writerow(["username", "password_hash"])
        
        # Потім проходимося по списку, хешуємо кожен пароль і записуємо в рядок
        for username, password in users_list:
            user_record = create_user(username, password)
            writer.writerow(user_record)
            
    print(f"\n[OK] Database successfully created/updated at the path:\n    {CSV_PATH}")

# Функція для читання нашої "бази даних" з файлу CSV
def read_database() -> list:
    users_db = []
    # Робимо красиву шапку для виводу в консоль
    print(f"\n--- Contents of the structured CSV database ---")
    print(f"{'Username':<15} | {'MD5 Hash'}")
    print("-" * 50)
    
    # Читаємо файл через DictReader (щоб звертатися до колонок за їхніми назвами, а не індексами)
    with open(CSV_PATH, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            users_db.append(row)
            print(f"{row['username']:<15} | {row['password_hash']}")
            
    return users_db

# Сама функція авторизації. До неї "прикріплений" наш декоратор @log_event
@log_event
def login(username: str, password: str, users_db: list) -> bool:
    if not username or not password:
        raise ValueError("Login and password cannot be empty.")
    
    # Хешуємо введений при спробі входу пароль
    attempt_hash = generate_hash(password, salt=PERSONAL_SALT)
    
    # Шукаємо юзера в базі. Якщо знайшли — перевіряємо, чи збігаються хеші
    for user_record in users_db:
        if user_record['username'] == username:
            return user_record['password_hash'] == attempt_hash
            
    # Якщо юзера не знайшли, або пароль не підійшов
    return False

# Головний блок програми (інтерфейс користувача)
def main():
    print("    USER REGISTRATION ")
    users_to_register = []
    
    # Блок try-except потрібен, щоб програма не "падала", якщо користувач введе щось не те
    try:
        count = int(input("How many users do you want to register? "))
        
        # Збираємо дані від користувача в циклі
        for i in range(1, count + 1):
            print(f"\nUser #{i}:")
            u = input("  Enter username: ").strip()
            p = input("  Enter password (min. 8 characters): ").strip()
            users_to_register.append((u, p))

        # Відправляємо на реєстрацію і запис у CSV
        create_users(users_to_register)
        
    # Тут ми відловлюємо наші кастомні та системні помилки і красиво виводимо їх на екран
    except ValidationError as e:
        print(f"\n[Validation Error]: {e}")
        return
    except ValueError as e:
        print(f"\n[Input/Value Error]: {e}")
        return
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"\n[File System Error]: {e}")
        return

    # Блок тестування входу (авторизації)
    try:
        users_db = read_database() # Зчитуємо те, що щойно записали
        print("\n   AUTHENTICATION (LOGIN) ")
        login_username = input("Enter username: ").strip()
        login_password = input("Enter password: ").strip()

        # Пробуємо зайти
        is_success = login(login_username, login_password, users_db)
        
        if is_success:
            print(f"\n[SUCCESS]: Login successful! Welcome, {login_username}.")
        else:
            print("\n[FAILURE]: Invalid username or password.")

    except ValueError as e:
        print(f"\n[Authentication Error]: {e}")
    except Exception as e:
        print(f"\n[Unexpected Error]: {e}")

# Цей рядок гарантує, що main() запуститься тільки якщо ми запускаємо саме цей файл, 
# а не імпортуємо його як модуль в інший скрипт
if __name__ == "__main__":
    main()