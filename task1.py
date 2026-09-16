import random
# Імпортуємо мої дані студента з іншого файлу (щоб було видно, чия це робота)
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

# Виводимо ПІБ, групу та номер варіанту на екран
print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)

# Тут я створила початковий список паролів, які ми будемо тестувати
passwords = ["SIEM@An4lysis", "easy123", "S0C@Analyst", "observer", 
"Threat@Hunt1ng", "viewer", "Incid3nt@Handle", "monitor", "Log@An4lysis", 
"watcher"]

# Задаємо критерії для ідеального пароля у вигляді словника:
# мінімальна довжина 9 символів, обов'язково цифри, великі літери та спецсимволи
criteria = {"min_length": 9, "require_digits": True, "require_upper": True, 
"require_special": True}

# Це наш "чорний список" (множина). Якщо пароль є тут, він автоматично вважається слабким
forbidden_passwords = {"easy123", "observer", "viewer", "monitor", "watcher", 
"admin"}

# Додаємо трохи випадковості: вибираємо 3 рандомні індекси з нашого списку паролів
random_indices = random.choices(range(len(passwords)), k=3)
# І дублюємо ці 3 випадкові паролі в кінець списку (наприклад, для тестування дублікатів)
for idx in random_indices:
    passwords.append(passwords[idx])

# Це головна функція перевірки надійності пароля. 
# (Зверни увагу: параметр називається passwords, але сюди передається лише один пароль за раз)
def check_password_strength(passwords, criteria, forbidden):
    # Одразу відсіюємо очевидно погані паролі: якщо він у словнику заборонених 
    # або його довжина менша за наш мінімум (9 символів) — повертаємо "Слабкий"
    if passwords in forbidden or len(passwords) < criteria["min_length"]:
        return "Слабкий пароль"

    # Далі перевіряємо наявність потрібних символів. 
    # any() пройдеться по кожному символу і поверне True, якщо знайде хоча б одну цифру
    has_digit = any(char.isdigit() for char in passwords)
    # Шукаємо хоча б одну велику літеру
    has_upper = any(char.isupper() for char in passwords)
    # А тут шукаємо спецсимвол (тобто це не буква, не цифра і не пробіл)
    has_special = any(not char.isalnum() and not char.isspace() for char in passwords)
    
    # Рахуємо, скільки додаткових умов ми виконали (максимум 3)
    criteria_met = sum([has_digit, has_upper, has_special])

    # Якщо виконані всі 3 умови, довжина пароля із запасом (на 4 символи більша за мінімальну) 
    # і сам пароль не містить внутрішніх дублікатів самого себе — це ідеал!
    if criteria_met == 3 and len(passwords) >= (criteria["min_length"] + 4) and passwords.count(passwords) == 1:
        return "Дуже сильний пароль"
    
    # Якщо просто виконані всі 3 умови (цифри, великі літери, спецсимволи), але він не такий довгий
    if criteria_met == 3:
        return "Сильний пароль"
    
    # Якщо виконалися тільки 1 або 2 умови з трьох
    if 0 < criteria_met < 3:
        return "Середній пароль"
    
    # Якщо нічого з цього не підійшло (що малоймовірно на цьому етапі, але для безпеки)
    return "Слабкий пароль"

# Робимо красиву шапку таблиці для виводу в консоль. 
# :<20 означає вирівнювання тексту по лівому краю з шириною 20 символів
print(f"{'Пароль':<20}|{'Надійність':<15}")
# Розділювач для краси
print("-" * 38)

# Проходимося циклом по нашому згенерованому списку паролів
for password in passwords:
    # Викликаємо нашу функцію для кожного окремого пароля
    strength = check_password_strength(password, criteria, forbidden_passwords)
    # Друкуємо результат у вигляді красивого рядка таблиці
    print(f"{password:<20}|{strength:<15}")