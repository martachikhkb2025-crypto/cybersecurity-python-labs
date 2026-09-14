from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
print (STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)

users = {
    "devsecops lead": {"role": "devsecops", "clearance": 4, "department": "DevSecOps", "active": True},
    "security_engineer": {"role": "security_engineer", "clearance": 3, "department": "Security Engineering", "active": True},
    "automation_tech": {"role": "automation", "clearance": 2, "department": "Automation", "active": True},
    "api_developer": {"role": "api_developer", "clearance": 2, "department": "API", "active": True},
    "sandbox_env": {"role": "sandbox", "clearance": 1, "department": "Testing", "active": False} 
} 

resources = [
    ("security pipelines", 4), ("secure_coding standards", 3), 
    ("automation_scripts", 2), ("api_specifications", 2), 
    ("threat_models", 4), ("testing_frameworks", 1), 
    ("security_gates", 3), ("vulnerability_scans", 4), 
    ("integration_tests", 2), ("mock_services", 1)
] 

security_levels = ("Sandbox", "Development", "Secure", "Production Critical") 
blocked_users = {"sandbox_env", "pipeline_breach", "automation_fail"}

def print_resources():
    print("                       Список ресурсів   ")
    for resource, level in resources:
        text_level = security_levels[level - 1]
        print(f"Ресурс: {resource}, Рівень безпеки: {text_level}")
print("-" * 30 + "\n")

def check_access(username, level):
    if username not in users:
        return "DENY (User not found)"
    
    if username in blocked_users:
        return "DENY (User is blocked)"
    
    user_data = users[username]

    if user_data["active"] == False:
        return "DENY (User is inactive)"
    
    if user_data["clearance"] >= level:
        return "ALLOW"
    else:
        return "DENY (Insufficient clearance)"
    
def run_access_control():
    users_to_test = list(users.keys()) + ["pipeline_breach", "automation_fail", "unknown_user"]

    print("   Результати перевірки доступу   ")
    for username in users_to_test:
        for resource, level in resources:
            result = check_access(username, level)
            print(f"user =[{username}] resource=[{resource}] -> {result}")

print_resources()
run_access_control()