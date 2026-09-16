# Підтягуємо мої дані (ПІБ, група, варіант), щоб було зрозуміло, чия це робота
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

# І виводимо це на екран, щоб було видно, чия це робота
print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)

# Це наша база даних користувачів. Зроблена як словник словників.
# Тут зберігається роль, рівень доступу (clearance), відділ і статус (активний/неактивний)
users = {
    "devsecops lead": {"role": "devsecops", "clearance": 4, "department": "DevSecOps", "active": True},
    "security_engineer": {"role": "security_engineer", "clearance": 3, "department": "Security Engineering", "active": True},
    "automation_tech": {"role": "automation", "clearance": 2, "department": "Automation", "active": True},
    "api_developer": {"role": "api_developer", "clearance": 2, "department": "API", "active": True},
    # Зверни увагу, цей юзер неактивний (False), ми це потім перевіримо
    "sandbox_env": {"role": "sandbox", "clearance": 1, "department": "Testing", "active": False} 
} 

# Це список ресурсів, до яких ми будемо просити доступ. 
# Зберігається як список кортежів (назва_ресурсу, необхідний_рівень_доступу)
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

# Функція для красивого виводу списку ресурсів перед початком тестування
def print_resources():
    print("                    Список ресурсів   ")
    # Проходимося по кожному ресурсу
    for resource, level in resources:
        # Тут ми віднімаємо 1 від рівня доступу, бо рівні йдуть від 1 до 4, 
        # а індекси в кортежі security_levels починаються з 0!
        text_level = security_levels[level - 1]
        print(f"Ресурс: {resource}, Рівень безпеки: {text_level}")
# Просто лінія для візуального розділення
print("-" * 30 + "\n")

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

    # 3. Якщо акаунт деактивовано — відмова
    if user_data["active"] == False:
        return "DENY (User is inactive)"
    
    # 4. І нарешті, якщо рівень доступу юзера більший або дорівнює 
    # рівню, який потрібен для ресурсу — пускаємо!
    if user_data["clearance"] >= level:
        return "ALLOW"
    else:
        # Інакше — відмова через недостатні права
        return "DENY (Insufficient clearance)"
    
# Ця функція запускає симуляцію перевірки для всіх
def run_access_control():
    # Беремо всіх реальних користувачів і спеціально додаємо кількох проблемних 
    # (з чорного списку та взагалі невідомих), щоб перевірити, чи спрацюють наші заборони
    users_to_test = list(users.keys()) + ["pipeline_breach", "automation_fail", "unknown_user"]

    print("   Результати перевірки доступу   ")
    # Подвійний цикл: для кожного користувача зі списку тестування...
    for username in users_to_test:
        # ...ми намагаємося "зайти" на кожен існуючий ресурс
        for resource, level in resources:
            # Викликаємо нашу функцію перевірки
            result = check_access(username, level)
            # І красиво друкуємо результат
            print(f"user =[{username}] resource=[{resource}] -> {result}")

# Власне, запускаємо код: спочатку показуємо ресурси, потім результати доступу
print_resources()
run_access_control()