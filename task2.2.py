import argparse  # Для обробки аргументів, що передаються через командний рядок (термінал)
import logging   # Для виведення повідомлень (логів) у консоль замість звичайного print()
import re        # Для роботи з регулярними виразами (пошук доменів у тексті пошти)
import csv       # Для створення та запису зібраних результатів у файл формату CSV
import sys       # Для системних операцій (наприклад, екстрене завершення програми у разі критичної помилки)

# Імпорт ідентифікаційних даних студента з локального модуля вашого проєкту
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
# Виведення інформації про студента у консоль під час запуску скрипта
print(f"Студент: {STUDENT_NAME}, Група: {GROUP_NAME}, Варіант: {VARIANT_NUMBER}")

# Функція для налаштування системи логування
def setup_logging(debug=False):
    # Якщо увімкнено режим debug (True), показуємо всі детальні повідомлення (DEBUG)
    # Інакше показуємо лише основні інформаційні повідомлення (INFO)
    level = logging.DEBUG if debug else logging.INFO
    # Встановлюємо простий формат виведення (лише сам текст повідомлення без дат і рівнів)
    logging.basicConfig(level=level, format='%(message)s')

# Функція для витягування домену з рядка електронної адреси
def extract_domain(email_str):
    # Якщо рядок порожній або взагалі відсутній, повертаємо None (нічого)
    if not email_str:
        return None
    # Шукаємо символ '@', а відразу після нього захоплюємо літери, цифри, крапки та дефіси
    match = re.search(r'@([\w.-]+)', email_str)
    # Якщо домен знайдено, повертаємо його в нижньому регістрі (щоб уникнути помилок при порівнянні 'Google.com' та 'google.com')
    # Якщо збігу немає (рядок не схожий на email), повертаємо None
    return match.group(1).lower() if match else None

# Функція для завантаження словника підозрілих слів (стоп-слів) із текстового файлу
def load_keywords(filepath):
    try:
        # Відкриваємо файл на читання з кодуванням UTF-8, щоб уникнути проблем із символами
        with open(filepath, 'r', encoding='utf-8') as f:
            # Проходимо по кожному рядку файлу
            # Видаляємо пробіли і невидимі символи з країв (strip)
            # Переводимо всі слова в нижній регістр (lower)
            # Додаємо у список тільки в тому випадку, якщо рядок не виявився порожнім
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        # Якщо вказаний файл не знайдено, записуємо помилку в лог
        logging.error(f"[ERROR] Словник {filepath} не знайдено.")
        # Завершуємо роботу програми з кодом помилки 1
        sys.exit(1)

# Головна функція для аналізу поштових заголовків на наявність ознак фішингу
def analyze_emails(log_path, keywords):
    try:
        # Відкриваємо файл логів як звичайний текст
        with open(log_path, 'r', encoding='utf-8') as f:
            # Зчитуємо весь вміст файлу в одну велику текстову змінну
            content = f.read()
        
        # Розбиваємо весь текст на окремі листи, використовуючи роздільник '--- MESSAGE ---'
        raw_emails = content.split('--- MESSAGE ---')
        # Створюємо порожній список, куди будемо складати словники з розібраними даними листів
        emails = []
        
        # Обробляємо кожен знайдений текстовий блок (окремий лист)
        for raw_email in raw_emails:
            # Видаляємо зайві пробіли або переноси рядків на початку та в кінці поточного блоку
            raw_email = raw_email.strip()
            # Якщо після очищення блок виявився порожнім (наприклад, порожній рядок в кінці файлу), ігноруємо його
            if not raw_email:
                continue
            
            # Створюємо словник для поточного листа. Поле 'Received' відразу робимо порожнім списком, бо їх може бути кілька
            email_dict = {'Received': []}
            # Розбиваємо текстовий блок листа на окремі рядки
            for line in raw_email.split('\n'):
                # Очищаємо рядок від пробілів
                line = line.strip()
                # Якщо рядок порожній або не містить двокрапки (тобто це не заголовок), пропускаємо його
                if not line or ':' not in line:
                    continue
                
                # Розділяємо рядок на ключ (назва заголовка) і значення по першій двокрапці
                key, value = line.split(':', 1)
                # Очищаємо ключ від зайвих пробілів
                key = key.strip()
                # Очищаємо значення від зайвих пробілів
                value = value.strip()
                
                # Якщо це унікальний ідентифікатор листа, записуємо його в словник під ключем 'id'
                if key == 'Message-ID':
                    email_dict['id'] = value
                # Якщо це інформація про маршрут листа (Received), додаємо це значення до списку
                elif key == 'Received':
                    email_dict['Received'].append(value)
                # Усі інші заголовки (Subject, From, Reply-To тощо) просто зберігаємо в словник як є
                else:
                    email_dict[key] = value
                    
            # Додаємо повністю сформований словник поточного листа до загального списку 'emails'
            emails.append(email_dict)

    except Exception as e:
        # Якщо виникла будь-яка інша помилка під час читання чи розбору файлу, виводимо її в лог
        logging.error(f"[ERROR] Помилка читання файлу логів: {e}")
        # Екстрено завершуємо програму
        sys.exit(1)

    # Виводимо інформаційні повідомлення про старт процесу аналізу
    logging.info(f"[INFO] Analyzing email headers dump from {log_path}...")
    logging.info(f"[INFO] Total emails inspected: {len(emails)}.\n")
    logging.info("=== Phishing & Spoofing Audit Results ===")

    # Створюємо список для збереження фінальних результатів перевірки кожного листа (піде у CSV)
    results = []

    # Проходимо по кожному розібраному листу зі списку 'emails'
    for email in emails:
        # Отримуємо значення потрібних полів. Якщо поля в листі немає, підставляємо значення за замовчуванням (пусті рядки)
        email_id = email.get('id', 'Unknown')
        subject = email.get('Subject', '')
        from_addr = email.get('From', '')
        return_path = email.get('Return-Path', '')
        reply_to = email.get('Reply-To', '')
        received = email.get('Received', [])

        # Ініціалізуємо початковий бал ризику (на старті лист вважається безпечним - 0 балів)
        score = 0      
        # Ініціалізуємо порожній список для фіксації виявлених проблем у цьому листі
        findings = []  

        # 1. Перевірка невідповідності доменів
        # Витягуємо домени з отриманих електронних адрес за допомогою нашої функції
        from_domain = extract_domain(from_addr)
        return_path_domain = extract_domain(return_path)
        reply_to_domain = extract_domain(reply_to)

        # Якщо домен відправника (From) і домен зворотної адреси (Return-Path) існують, але відрізняються
        # Це яскрава ознака підміни відправника (Spoofing)
        if from_domain and return_path_domain and from_domain != return_path_domain:
            # Додаємо 30 балів ризику
            score += 30
            # Записуємо суть проблеми у список знахідок
            findings.append(f"Sender Mismatch : From: \"{from_addr}\" vs Return-Path: \"{return_path}\"")

        # Аналогічно перевіряємо розбіжність доменів From та адреси для відповіді (Reply-To)
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            score += 30
            findings.append(f"Reply-To Mismatch: \"{reply_to}\"")

        # 2. Пошук підозрілих слів (стоп-слів) у темі листа
        found_words = []
        # Переводимо тему листа в нижній регістр, щоб пошук не залежав від великих чи малих літер
        subject_lower = subject.lower()
        
        # Перевіряємо кожне ключове слово з нашого завантаженого словника
        for kw in keywords:
            # Якщо ключове слово знайдено в темі листа
            if kw in subject_lower:
                # Додаємо це слово до списку знайдених, роблячи його ВЕЛИКИМ для наочності у звіті
                found_words.append(kw.upper()) 

        # Якщо були знайдені хоч якісь підозрілі слова
        if found_words:
            # Додаємо по 10 балів ризику за кожне знайдене стоп-слово
            score += 10 * len(found_words)
            # Додаємо інформацію про знайдені слова до списку проблем листа
            findings.append(f"Stopwords Found : {found_words}")

        # 3. Обчислення кількості проміжних вузлів ретрансляції (Hop Count)
        # Якщо 'received' - це список, дізнаємося його довжину (кількість серверів). 
        # Якщо ні (наприклад один рядок), то вузол був 1.
        hop_count = len(received) if isinstance(received, list) else 1
        # Якщо вузлів більше 5, це вважається аномально довгим маршрутом для листа
        if hop_count > 5:
            # Додаємо 10 балів ризику
            score += 10
            # Фіксуємо проблему
            findings.append(f"Hop Count       : {hop_count} intermediate relays (Abnormal)")

        # Обмежуємо максимальний загальний бал ризику цифрою 100
        score = min(score, 100)

        # Визначаємо рівень загрози (Risk Level) та текстовий префікс для логування залежно від балів
        if score >= 70:
            risk_level = "CRITICAL PHISHING SUSPECT"
            prefix = "[HIGH RISK]"
        elif score >= 40:
            risk_level = "SUSPICIOUS"
            prefix = "[MEDIUM RISK]"
        else:
            risk_level = "CLEAN"
            prefix = "[INFO]"

        # Якщо лист набрав хоча б один бал ризику, виводимо його розбір у консоль
        if score > 0:
            # Виводимо загальну інформацію про лист (ID, Тема) з префіксом ризику
            logging.info(f"{prefix} Email ID {email_id} | Subject: \"{subject}\"")
            # Перебираємо всі знайдені проблеми і виводимо їх одну за одною з відступом
            for finding in findings:
                logging.info(f"  - {finding}")
            # Виводимо підсумковий бал і рівень ризику для цього листа
            logging.info(f"  - Risk Score      : {score}/100 ({risk_level})\n")

        # Формуємо словник з підсумковими результатами перевірки поточного листа
        # і додаємо його до загального списку результатів (для подальшого експорту в CSV)
        results.append({
            'ID': email_id,
            'Subject': subject,
            'From': from_addr,
            'Score': score,
            'Risk_Level': risk_level
        })

    # Після перевірки всіх листів функція повертає загальний список результатів
    return results

# Функція для збереження звіту з результатами у CSV-файл
def save_report(results, out_csv):
    try:
        # Відкриваємо файл на запис (режим 'w'). 
        # Параметр newline='' обов'язковий, щоб уникнути порожніх рядків між записами в ОС Windows
        with open(out_csv, 'w', newline='', encoding='utf-8') as f:
            # Ініціалізуємо CSV DictWriter. Вказуємо назви колонок (fieldnames), які мають збігатися з ключами у словниках results
            writer = csv.DictWriter(f, fieldnames=['ID', 'Subject', 'From', 'Score', 'Risk_Level'])
            # Спочатку записуємо перший рядок у файл - заголовки колонок
            writer.writeheader()
            # Записуємо всі дані відразу зі списку results (передаємо список словників)
            writer.writerows(results)
        # Логуємо повідомлення про успішне збереження звіту
        logging.info(f"[INFO] Phishing audit summary exported to {out_csv}")
    except Exception as e:
        # Якщо виникла помилка під час запису (наприклад, немає прав доступу або файл відкритий в Excel), логуємо її
        logging.error(f"[ERROR] Помилка запису CSV: {e}")

# Цей блок коду є точкою входу програми. Він виконується ТІЛЬКИ якщо скрипт запускається напряму з терміналу
# (Якщо скрипт імпортувати як модуль в інший Python-файл, цей код проігнорується)
if __name__ == "__main__":
    # Створюємо об'єкт парсера для зчитування параметрів, які користувач передає у командному рядку
    parser = argparse.ArgumentParser(description="Аналізатор заголовків електронної пошти та фішингових індикаторів")
    
    # Додаємо обов'язковий аргумент (--mail-log) для вказання шляху до файлу з поштовими логами
    parser.add_argument("--mail-log", required=True, help="Шлях до файлу з дампами заголовків")
    # Додаємо обов'язковий аргумент (--suspicious-keywords) для вказання шляху до файлу зі стоп-словами
    parser.add_argument("--suspicious-keywords", required=True, help="Шлях до файлу зі словником стоп-слів")
    # Додаємо обов'язковий аргумент (--out-csv) для вказання шляху, куди програма має зберегти звіт
    parser.add_argument("--out-csv", required=True, help="Шлях для збереження CSV звіту")
    # Додаємо необов'язковий прапорець (--debug) для увімкнення розширеного логування (action="store_true" означає, що якщо прапорець є, значення буде True)
    parser.add_argument("--debug", action="store_true", help="Увімкнути режим налагодження (debug)")

    # Зчитуємо та розбираємо аргументи з терміналу
    args = parser.parse_args()
    
    # Налаштовуємо рівень логування на основі переданого аргументу --debug
    setup_logging(args.debug)
    
    # Якщо користувач увімкнув режим debug, виводимо тестове повідомлення
    if args.debug:
        logging.debug("[DEBUG] Режим налагодження увімкнено.")

    # 1. Завантажуємо список підозрілих слів, використовуючи шлях, переданий з терміналу
    keywords_list = load_keywords(args.suspicious_keywords)
    
    # 2. Виконуємо аналіз листів, передавши шлях до файлу пошти та сформований список слів
    analysis_results = analyze_emails(args.mail_log, keywords_list)
    
    # 3. Зберігаємо отримані результати аналізу у CSV-файл за вказаним у терміналі шляхом
    save_report(analysis_results, args.out_csv)

    #cd labs\lab02
    #python task2.py --mail-log data\mail_headers.log --suspicious-keywords data\suspicious_keywords.txt --out-csv data\phishing_report.csv