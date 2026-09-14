import random
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
print (STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)

passwords = ["SIEM@An4lysis", "easy123", "S0C@Analyst", "observer", 
"Threat@Hunt1ng", "viewer", "Incid3nt@Handle", "monitor", "Log@An4lysis", 
"watcher"]
criteria = {"min_length": 9, "require_digits": True, "require_upper": True, 
"require_special": True}
forbidden_passwords = {"easy123", "observer", "viewer", "monitor", "watcher", 
"admin"}

random_indices = random.choices(range(len(passwords)), k=3)
for idx in random_indices:
    passwords.append(passwords[idx])

def check_password_strength(passwords, criteria, forbidden):
    if passwords in forbidden or len(passwords) < criteria["min_length"]:
        return "Слабкий пароль"

    has_digit = any(char.isdigit() for char in passwords)
    has_upper = any(char.isupper() for char in passwords)
    has_special = any(not char.isalnum() and not char.isspace() for char in passwords)
    
    criteria_met = sum([has_digit, has_upper, has_special])

    if criteria_met == 3 and len(passwords) >= (criteria["min_length"] + 4) and passwords.count(passwords) == 1:
        return "Дуже сильний пароль"
    
    if criteria_met == 3:
        return "Сильний пароль"
    
    if 0 < criteria_met < 3:
        return "Середній пароль"
    
    return "Слабкий пароль"

print(f"{'Пароль':<20}|{'Надійність':<15}")
print("-" * 38)

for password in passwords:
    strength = check_password_strength(password, criteria, forbidden_passwords)
    print(f"{password:<20}|{strength:<15}")
