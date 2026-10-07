import os
import re
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import List, Set, Optional

# Імпорт ідентифікаційних даних студента з локального модуля (згідно зі структурою вашого проєкту)
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
# Виведення інформації про студента у консоль при запуску скрипта
print(f"Студент: {STUDENT_NAME}, Група: {GROUP_NAME}, Варіант: {VARIANT_NUMBER}")

# Кількість ітерацій для алгоритму PBKDF2 (чим більше, тим надійніше, але повільніше)
ITERATIONS = 100_000
# Час життя сесії у секундах (900 секунд = 15 хвилин)
SESSION_TIMEOUT_SEC = 900

# Клас, що описує базову модель користувача
class User:
    # Конструктор класу, який ініціалізує основні атрибути користувача
    def __init__(self, username: str, email: str, role: str = "user", active: bool = True):
        # Публічний атрибут для збереження імені користувача
        self.username = username
        # Прихований (protected) атрибут для збереження email
        self._email = None
        # Виклик сеттера для email (для перевірки формату під час створення об'єкта)
        self.email = email  
        # Роль користувача (за замовчуванням 'user')
        self.role = role
        # Статус акаунта (активний чи ні)
        self.active = active
        # Приватний атрибут для збереження хешу пароля (початково порожній рядок байтів)
        self.__password_hash = b""
        # Приватний атрибут для збереження солі пароля (початково порожній рядок байтів)
        self.__password_salt = b""

    # Декоратор property перетворює метод email на властивість (геттер)
    @property
    def email(self) -> str:
        # Повертає значення захищеного атрибута
        return self._email

    # Декоратор setter для властивості email (спрацьовує при спробі змінити email)
    @email.setter
    def email(self, value: str):
        # Регулярний вираз для валідації: починається з літери, 3-64 символи локальної частини, символ @ і домен
        pattern = r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        # Перевіряємо, чи передане значення відповідає шаблону
        if not re.match(pattern, value):
            # Якщо не відповідає, генеруємо виняток ValueError
            raise ValueError("Невірний формат email")
        # Якщо все добре, зберігаємо email
        self._email = value

    # Метод для встановлення (або зміни) пароля
    def set_password(self, password: str):
        # Генеруємо унікальну випадкову сіль довжиною 32 байти
        self.__password_salt = os.urandom(32)
        # Створюємо хеш пароля алгоритмом PBKDF2 з використанням SHA-256, солі та заданої кількості ітерацій
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode('utf-8'),
            self.__password_salt,
            ITERATIONS
        )

    # Метод для перевірки правильності введеного пароля
    def check_password(self, password: str) -> bool:
        # Якщо пароль ще не був встановлений, відразу повертаємо False
        if not self.__password_hash or not self.__password_salt:
            return False
        # Хешуємо введений пароль з тією ж сіллю, яка була збережена
        test_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode('utf-8'),
            self.__password_salt,
            ITERATIONS
        )
        # Використовуємо compare_digest для захисту від атак за часом, порівнюючи хеші
        return hmac.compare_digest(self.__password_hash, test_hash)

    # Метод для деактивації профілю користувача
    def deactivate(self):
        # Змінюємо статус на False
        self.active = False

    # Магічний метод для зручного відображення об'єкта як рядка (наприклад, під час print)
    def __str__(self):
        return f"User(username='{self.username}', email='{self.email}', role='{self.role}', active={self.active})"

# Клас Адміністратора, який наслідує (успадковує) клас User
class Admin(User):
    # Конструктор адміністратора з додатковим аргументом permissions (дозволи)
    def __init__(self, username: str, email: str, role: str = "admin", active: bool = True, permissions: Optional[Set[str]] = None):
        # Виклик конструктора батьківського класу (User)
        super().__init__(username, email, role, active)
        # Якщо дозволи передані, створюємо з них множину, інакше створюємо порожню множину
        self.permissions = set(permissions) if permissions is not None else set()

    # Метод для надання нового дозволу адміністратору
    def grant_permission(self, permission: str):
        # Додаємо дозвіл до множини
        self.permissions.add(permission)

    # Метод для відкликання (видалення) дозволу в адміністратора
    def revoke_permission(self, permission: str):
        # Видаляємо дозвіл безпечно (discard не викличе помилку, якщо такого дозволу немає)
        self.permissions.discard(permission)

    # Метод для перевірки, чи є у адміністратора певний дозвіл
    def has_permission(self, permission: str) -> bool:
        # Повертає True, якщо дозвіл є у множині
        return permission in self.permissions

    # Перевизначення методу __str__ для виведення дозволів разом з основними даними
    def __str__(self):
        # Отримуємо базовий рядок від класу User
        base_str = super().__str__()
        # Відрізаємо останню дужку ')' і додаємо дозволи
        return f"{base_str[:-1]}, permissions={self.permissions})"

# Клас для керування сеансом (сесією) користувача
class Session:
    # Конструктор ініціалізує сесію з IP-адресою
    def __init__(self, ip: str):
        # Зберігаємо IP
        self.ip = ip
        # Записуємо точний час створення сесії у форматі UTC
        self.login_time = datetime.now(timezone.utc)
        # Одразу після створення, час останньої активності дорівнює часу входу
        self.last_activity = self.login_time

    # Метод для оновлення часу останньої активності (наприклад, при кожній дії користувача)
    def touch(self):
        # Записуємо поточний UTC час
        self.last_activity = datetime.now(timezone.utc)

    # Метод для перевірки, чи дійсна ще сесія
    def is_active(self, timeout_sec: int) -> bool:
        # Якщо таймаут некоректний (менше або дорівнює нулю), сесія неактивна
        if timeout_sec <= 0:
            return False
        # Беремо поточний UTC час
        now = datetime.now(timezone.utc)
        # Якщо різниця між зараз і останньою активністю менша або дорівнює дозволеному таймауту — повертаємо True
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)

# Використання декоратора dataclass для створення структури даних одного запису журналу подій
@dataclass
class LogEntry:
    # Час події
    timestamp: datetime
    # Ім'я користувача, якого стосується подія
    username: str
    # Назва дії (наприклад, 'login_success')
    action: str

# Клас журналу аудиту для зберігання всіх подій системи
class AuditLog:
    # Конструктор ініціалізує порожній список для записів
    def __init__(self):
        self.logs: List[LogEntry] = []

    # Метод для додавання нового запису в журнал
    def add_log(self, username: str, action: str):
        # Створюємо об'єкт LogEntry і додаємо його в список logs
        self.logs.append(LogEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action
        ))

    # Метод для виведення всіх записів журналу у консоль
    def show_all(self):
        # Перебираємо всі записи
        for log in self.logs:
            # Виводимо їх у форматованому вигляді
            print(f"[{log.timestamp.isoformat()}] User: {log.username} | Action: {log.action}")

# Клас, який об'єднує користувача, його сесію та журнал аудиту (Композиція)
class UserAccount:
    # Конструктор приймає об'єкт користувача і необов'язковий об'єкт журналу
    def __init__(self, user: User, audit_log: Optional[AuditLog] = None):
        # Зберігаємо об'єкт User
        self.user = user
        # Початково сесія відсутня
        self.session: Optional[Session] = None
        # Якщо журнал передали — використовуємо його, інакше створюємо новий
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    # Метод для входу в систему (створення сесії)
    def login(self, username: str, password: str, ip: str) -> bool:
        # Перевірка: чи користувач активний і чи співпадає логін
        if not self.user.active or self.user.username != username:
            # Якщо ні — фіксуємо невдалий вхід в аудиті
            self.audit_log.add_log(username, "login_failure")
            return False

        # Якщо пароль правильний
        if self.user.check_password(password):
            # Створюємо об'єкт сесії
            self.session = Session(ip)
            # Оновлюємо час останньої активності
            self.session.touch()
            # Записуємо успішний вхід в журнал
            self.audit_log.add_log(username, "login_success")
            return True
        else:
            # Якщо пароль неправильний — фіксуємо помилку
            self.audit_log.add_log(username, "login_failure")
            return False

    # Метод для перевірки, чи авторизований користувач зараз
    def is_authenticated(self) -> bool:
        # Якщо об'єкта сесії немає взагалі — не авторизований
        if self.session is None:
            return False
        # Перевіряємо, чи не закінчився таймаут сесії
        if self.session.is_active(SESSION_TIMEOUT_SEC):
            return True
        return False

    # Метод для виходу із системи
    def logout(self):
        # Якщо сесія існує
        if self.session:
            # Видаляємо об'єкт сесії
            self.session = None
            # Фіксуємо вихід в журналі аудиту
            self.audit_log.add_log(self.user.username, "logout")

    # Магічний метод для отримання атрибутів через квадратні дужки (account['user'])
    def __getitem__(self, key: str):
        # Якщо запитали ключ 'user', повертаємо об'єкт користувача
        if key == "user":
            return self.user
        # Якщо 'session', повертаємо об'єкт сесії
        elif key == "session":
            return self.session
        # Якщо 'audit_log', повертаємо об'єкт журналу
        elif key == "audit_log":
            return self.audit_log
        # Якщо ключ невідомий — викликаємо помилку ключа
        else:
            raise KeyError(f"Невідомий ключ: {key}")

    # Магічний метод для встановлення значень через квадратні дужки (account['user'] = new_user)
    def __setitem__(self, key: str, value):
        # Встановлення нового користувача
        if key == "user":
            # Перевіряємо тип значення
            if not isinstance(value, User):
                raise TypeError("Значення має бути типу User")
            self.user = value
        # Встановлення нової сесії
        elif key == "session":
            # Сесія може бути Session або None
            if value is not None and not isinstance(value, Session):
                raise TypeError("Значення має бути типу Session або None")
            self.session = value
        # Встановлення нового журналу аудиту
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Значення має бути типу AuditLog")
            self.audit_log = value
        # Невідомий ключ
        else:
            raise KeyError(f"Невідомий ключ: {key}")

# Функція для демонстрації роботи усіх створених класів
def demo():
    # Заголовок для консолі
    print("--- Демонстрація Моделі користувача ---")
    
    # Створення тестового користувача
    user1 = User("testuser", "validemail123@example.com")
    # Встановлення пароля для нього
    user1.set_password("SecureP@ss1")
    # Виведення даних через магічний метод __str__
    print(f"Створено: {user1}")
    
    # Блок try-except для тестування валідації некоректного email
    try:
        user1.email = "1invalid_email"
    except ValueError as e:
        print(f"Помилка при невірному email: {e}")

    # Створення тестового адміністратора
    admin = Admin("superadmin", "admin@domain.com")
    # Надання йому дозволу на читання логів
    admin.grant_permission("read_logs")
    # Виведення даних адміністратора (покаже також множину дозволів)
    print(f"Адміністратор: {admin}")

    # Створення облікового запису на базі user1
    account = UserAccount(user1)
    
    # Тест: спроба авторизації з неправильним паролем
    print("\nСпроба входу з невірним паролем...")
    account.login("testuser", "WrongPass", "192.168.0.1")
    
    # Тест: спроба авторизації з правильним паролем
    print("Спроба входу з вірним паролем...")
    account.login("testuser", "SecureP@ss1", "192.168.0.1")
    # Перевірка статусу авторизації (має бути True)
    print(f"Аутентифіковано: {account.is_authenticated()}")

    # Тест перевірки таймауту сесії
    if account.session:
        # Штучно зменшуємо час останньої активності на 1000 секунд у минуле
        account.session.last_activity = datetime.now(timezone.utc) - timedelta(seconds=1000)
        # Тепер перевірка покаже False, оскільки 1000 > 900 (SESSION_TIMEOUT_SEC)
        print(f"Аутентифіковано після таймауту (>900 сек): {account.is_authenticated()}")

    # Повторний успішний вхід
    account.login("testuser", "SecureP@ss1", "192.168.0.1")
    # Тестування виходу (знищує сесію)
    account.logout()
    # Перевірка після виходу (має бути False)
    print(f"Аутентифіковано після виходу: {account.is_authenticated()}")

    # Виведення всіх записів журналу аудиту, щоб побачити успішні входи, помилки та виходи
    print("\n--- Записи AuditLog ---")
    account.audit_log.show_all()

# Точка входу в програму. Виконується, якщо скрипт запущено безпосередньо (не через імпорт)
if __name__ == "__main__":
    # Запускаємо функцію демонстрації
    demo()