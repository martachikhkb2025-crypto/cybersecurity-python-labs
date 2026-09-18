# Підтягуємо мої дані (ПІБ, група, варіант), і виводимо в терміналі
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)

# Тут зберігається роль, рівень доступу , відділ і статус
users = {
    "devsecops lead": {"role": "devsecops", "clearance": 4, "department": "DevSecOps", "active": True},
    "security_engineer": {"role": "security_engineer", "clearance": 3, "department": "Security Engineering", "active": True},
    "automation_tech": {"role": "automation", "clearance": 2, "department": "Automation", "active": True},
    "api_developer": {"role": "api_developer", "clearance": 2, "department": "API", "active": True},
    "sandbox_env": {"role": "sandbox", "clearance": 1, "department": "Testing", "active": False} 
} 

# Це список ресурсів, до яких ми будемо просити доступ. 
resources = [
    ("security pipelines", 4), ("secure_coding standards", 3), 
    ("automation_scripts", 2), ("api_specifications", 2), 
    ("threat_models", 4), ("testing_frameworks", 1), 
    ("security_gates", 3), ("vulnerability_scans", 4), 
    ("integration_tests", 2), ("mock_services", 1)
] 

# Це текстові назви для наших рівнів доступу (від 1 до 4)
security_levels = ("Sandbox", "Development", "Secure", "Production Critical") 
# А це "чорний список" — ті, кому доступ завжди закритий
blocked_users = {"sandbox_env", "pipeline_breach", "automation_fail"}

# Додаткова функція (Крок 2): виводить ресурси із їхніми текстовими рівнями доступу
def display_resources():
    print("   Список ресурсів системи   ")
    for resource, level in resources:
        level_name = security_levels[level - 1]
        print(f"Ресурс: {resource} | Рівень: {level_name}")
    print("-" * 31 + "\n")

# Найголовніша функція! Тут прописана вся логіка прийняття рішень: пустити чи ні.
def check_access(username, level):
    # 1. Якщо такого користувача взагалі немає в базі — відмова
    if username not in users:
        return "DENY (User not found)"
    
    # 2. Якщо користувач у нашому чорному списку — відмова
    if username in blocked_users:
        return "DENY (User is blocked)"
    
    # Дістаємо дані нашого юзера
    user_data = users[username]

    # 3. Якщо акаунт деактивовано — відмова (текст змінено згідно умови)
    if user_data["active"] == False:
        return "DENY (Account inactive)"

    # 4. Якщо рівень доступу юзера більший або дорівнює — пускаємо
    if user_data["clearance"] >= level:
        return "ALLOW"
    else:
        # Інакше — відмова через недостатні права
        return "DENY (Insufficient clearance)"
    
# Ця функція запускає симуляцію перевірки для всіх
def run_access_control():
    # Спочатку виводимо всі ресурси (згідно умови)
    display_resources()
    
    # Беремо всіх реальних користувачів і спеціально додаємо кількох проблемних 
    users_to_test = list(users.keys()) + ["pipeline_breach", "automation_fail", "unknown_user"]

    print("   Результати перевірки доступу   ")
    # Подвійний цикл: для кожного користувача зі списку тестування...
    for username in users_to_test:
        # ...ми намагаємося "зайти" на кожен існуючий ресурс
        for resource, level in resources:
            # Викликаємо нашу функцію перевірки
            result = check_access(username, level)
            # Вивід змінено згідно умови: без пробілів біля =
            print(f"user=[{username}] resource=[{resource}] -> {result}")

# Власне, запускаємо код: спочатку показуємо ресурси, потім результати доступу
run_access_control()