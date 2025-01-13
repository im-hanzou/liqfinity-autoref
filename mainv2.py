import random
import string
import names
import os
import json
from fake_useragent import UserAgent
from curl_cffi import requests
from curl_cffi.requests.errors import RequestsError, CurlError
from datetime import datetime
from colorama import init, Fore, Style
import time

init(autoreset=True)
ua = UserAgent()
TURNSTILE_TOKEN = "0.FfIEG5oZ4yq3L-M57HokEMwaIakhint8OjzZ84VtQ28CpeddmvQfHOXZokIzmlJ2pPMaWB3FjlfamCvZTb2fe2M1V6RCRontsW0p7U4jbCNkphukg8CiGTKL7Km8eoyagY-qxHLluWN8DzPCelCWuPLzNTSCw7qT_xggV4HKJzsRAiahASW691g8z31hTvDwJXdLdA52uvrdKqPa0c4XE4_j4leJXMJHyJQiArpz4jyA1GcSpuVMVqEFJEc3hnoRyuazNrmbVOGhpoev3kKfBLht9N_TLN7kXPEz3moKt3_-2qBriFNDESh7AVyiFrTO73NrpLP35FGXwsU7RZaXpp18UnRgBgjjqRG0ghXrFHZvbNzxQwPj9fpRlAir-WMoQX57bqGwD5ZDbgNhfEA14MtH45Ud1p4CwcTlFB-a94hfyuTWSmCHON1NgBvSK4JtLYynpEdMwLmiFSP43T147mbX9iI8dGV01LtTM_kM6wu4w9-ayS5raY1lE68duKAWQgJzgP7Tx-YJ3MT1gpf60jab5uEolX6Lb6ypI2moWqtffyq_r0yS3THtVWOqFIX0A1ZTYT-nLPvAyRiWLf_FDFTB2BgwPlcIHg3v1Y3AVB5OuUrNnL5BjW6aGcefETeEHNy3w7EXuo2zb0bNOq3KXNOku8otlxbuKou7Yzoy3XR21VSGwbsJyHqPhQ8p513m65Tdfv9zBSS0P6fbwsLC7zJIk0ZZkRgdpyyNbxcdJrzXerFnZiqFfptZadr5DDpxAjzx5VD-TGokUApCibUb7TDQEapto8Iyx5uurnCYC1M.-OcEkJegvUKjwxUIJevy5A.a353483113dea92b789175686a993bc73260bc06728a439df833557144446b7c"
WEBSITE_URL = "https://app.testnet.liqfinity.com"
MAX_RETRIES = 10
CURRENT_ACCOUNT = 0
TOTAL_ACCOUNTS = 0

def log_message(message, color=Fore.LIGHTCYAN_EX, show_progress=True):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    progress = f" [{CURRENT_ACCOUNT}/{TOTAL_ACCOUNTS}]" if show_progress and TOTAL_ACCOUNTS > 0 else ""
    print(f"{Fore.WHITE}[{Fore.LIGHTBLACK_EX}{timestamp}{Fore.WHITE}]{progress} {color}{message}{Style.RESET_ALL}")

def make_request_with_retry(request_func, max_retries=MAX_RETRIES):
    retry_count = 0
    while retry_count < max_retries:
        try:
            return request_func()
        except Exception as e:
            error_str = str(e)
            if "Failed to perform" in error_str and "curl" in error_str:
                retry_count += 1
                if retry_count < max_retries:
                    log_message(f"Curl perform error, retrying... ", Fore.LIGHTYELLOW_EX)
                    continue
            raise  
    return None

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.load_proxies()
        
    def load_proxies(self):
        try:
            if os.path.exists('proxies.txt') and os.path.getsize('proxies.txt') > 0:
                with open('proxies.txt', 'r') as f:
                    self.proxies = [line.strip() for line in f if line.strip()]
                print(f"{Fore.LIGHTGREEN_EX}Loaded proxies from proxies.txt\n", Style.RESET_ALL)
            else:
                print(f"{Fore.LIGHTYELLOW_EX}WARNING: proxies.txt not found or empty. Using direct connection.\n", Style.RESET_ALL)
        except Exception as e:
            print(f"{Fore.LIGHTRED_EX}Error loading proxies: {str(e)}\n", Style.RESET_ALL)
            
    def get_random_proxy(self):
        if not self.proxies:
            return None
        proxy = random.choice(self.proxies)
        return {
            "http": f"{proxy}",
            "https": f"{proxy}"
        }

def get_headers():
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'origin': 'https://app.testnet.liqfinity.com',
        'priority': 'u=1, i',
        'referer': 'https://app.testnet.liqfinity.com/',
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': ua.chrome
    }
    return headers

def generate_password():
    first_letter = random.choice(string.ascii_uppercase)
    letters = ''.join(random.choices(string.ascii_lowercase, k=8))
    numbers = ''.join(random.choices(string.digits, k=4))
    special = random.choice('!@#$%^&*')
    password = f"{first_letter}{letters}{numbers}{special}"
    return password

def get_random_domain(proxies):
    log_message("Searching for available email domain...")
    vowels = 'aeiou'
    consonants = 'bcdfghjklmnpqrstvwxyz'
    keyword = random.choice(consonants) + random.choice(vowels)
    
    def make_domain_request():
        return requests.get(
            f'https://generator.email/search.php?key={keyword}',
            headers=get_headers(),
            proxies=proxies,
            impersonate="chrome110",
            timeout=120,
            verify=False
        )
    
    try:
        response = make_request_with_retry(make_domain_request)
        if not response:
            log_message("Failed to get domain after maximum retries", Fore.LIGHTRED_EX)
            return None
            
        domains = response.json()
        valid_domains = [d for d in domains if all(ord(c) < 128 for c in d)]
        
        if valid_domains:
            selected_domain = random.choice(valid_domains)
            log_message(f"Selected domain: {selected_domain}", Fore.LIGHTGREEN_EX)
            return selected_domain
            
        log_message("Could not find valid domain", Fore.LIGHTRED_EX)
        return None
            
    except Exception as e:
        log_message(f"Error getting domain: {str(e)}", Fore.LIGHTRED_EX)
        return None

def generate_email(domain):
    log_message("Generating email address...")
    first_name = names.get_first_name().lower()
    last_name = names.get_last_name().lower()
    random_nums = ''.join(random.choices(string.digits, k=3))
    
    separator = random.choice(['', '.'])
    email = f"{first_name}{separator}{last_name}{random_nums}@{domain}"
    log_message(f"Email created: {email}", Fore.LIGHTGREEN_EX)
    return email

def register_account(ref_code, proxies):
    def make_register_request(email, password):
        data = {
            "password": password,
            "email": email,
            "referrerCode": ref_code,
            "turnstileToken": TURNSTILE_TOKEN
        }
        return requests.post(
            'https://api.testnet.liqfinity.com/v1/auth/register',
            headers=get_headers(),
            json=data,
            proxies=proxies,
            impersonate="chrome110",
            timeout=120,
            verify=False
        )

    retry_count = 0
    while retry_count < MAX_RETRIES:
        try:
            domain = get_random_domain(proxies)
            if not domain:
                log_message("Failed to get valid domain", Fore.LIGHTRED_EX)
                return None, None, None
                
            email = generate_email(domain)
            password = generate_password()
            log_message(f"Registering account with referral code: {ref_code}...")

            response = make_request_with_retry(
                lambda: make_register_request(email, password)
            )
            
            if not response:
                log_message("Failed to register after maximum retries", Fore.LIGHTRED_EX)
                return None, None, None
            
            if response.status_code == 200:
                resp_json = response.json()
                if resp_json.get('message') == 'Signup successfull':
                    log_message(f"Registration successful for {email}", Fore.LIGHTGREEN_EX)
                    return email, password, resp_json['data']['user']['referrerCode']
            elif response.status_code in [429, 502, 503, 504]:
                log_message(f"Server error ({response.status_code}), retrying registration...", Fore.LIGHTYELLOW_EX)
                retry_count += 1
                if retry_count < MAX_RETRIES:
                    continue
                else:
                    log_message(f"Maximum registration retries reached", Fore.LIGHTRED_EX)
                    return None, None, None
            else:
                log_message(f"Registration failed with status {response.status_code}", Fore.LIGHTRED_EX)                
                return None, None, None
                
        except Exception as e:
            retry_count += 1
            if retry_count < MAX_RETRIES:
                log_message(f"Registration failed: {str(e)}, retrying registration... ", Fore.LIGHTYELLOW_EX)
                continue
            else:
                log_message(f"Maximum registration retries reached", Fore.LIGHTRED_EX)
                return None, None, None
            
    return None, None, None

def login_account(email, password, proxies):
    def make_login_request():
        data = {
            "email": email,
            "password": password,
            "turnstileToken": TURNSTILE_TOKEN
        }
        return requests.post(
            'https://api.testnet.liqfinity.com/v1/auth/login',
            headers=get_headers(),
            json=data,
            proxies=proxies,
            impersonate="chrome110",
            timeout=120,
            verify=False
        )
    
    retry_count = 0
    while retry_count < MAX_RETRIES:
        try:
            log_message(f"Logging in account {email}...")
                
            response = make_request_with_retry(lambda: make_login_request())
            if not response:
                return None, None
            
            if response.status_code == 200:
                resp_json = response.json()
                if resp_json.get('message') == 'Login successful':
                    log_message(f"Login successful for {email}", Fore.LIGHTGREEN_EX)
                    return resp_json['data']['accessToken'], resp_json['data']['refreshToken']
            elif response.status_code in [429, 502, 503, 504]:
                retry_count += 1
                if retry_count < MAX_RETRIES:
                    log_message(f"Server error ({response.status_code}), retrying login... ", Fore.LIGHTYELLOW_EX)
                    continue
                else:
                    log_message("Maximum login retries reached", Fore.LIGHTRED_EX)
                    return None, None
            else:
                log_message(f"Login failed with status {response.status_code}", Fore.LIGHTRED_EX)
                return None, None
        except Exception as e:
            retry_count += 1
            if retry_count < MAX_RETRIES:
                log_message(f"Login error: {str(e)}. Retrying... ", Fore.LIGHTYELLOW_EX)
                continue
            else:
                log_message(f"Login failed after {MAX_RETRIES} attempts: {str(e)}", Fore.LIGHTRED_EX)
                return None, None
    
    return None, None

def setup_account(access_token, proxies, email):
    if not access_token:
        return False
    
    def make_setup_request():
        headers = get_headers()
        headers['authorization'] = f'Bearer {access_token}'
        return requests.post(
            'https://api.testnet.liqfinity.com/v1/user/account/setup',
            headers=headers,
            proxies=proxies,
            impersonate="chrome110",
            timeout=120,
            verify=False
        )
    
    retry_count = 0
    while retry_count < MAX_RETRIES:
        try:
            log_message(f"Setting up account {email}...")
            response = make_request_with_retry(make_setup_request)
            if not response:
                return False
            
            if response.status_code == 200:
                resp_json = response.json()
                if resp_json.get('message') == 'Account setup successfull':
                    log_message("Account setup successful", Fore.LIGHTGREEN_EX)
                    return True
            elif response.status_code in [429, 502, 503, 504]:
                retry_count += 1
                if retry_count < MAX_RETRIES:
                    log_message(f"Server error ({response.status_code}), retrying setup... ", Fore.LIGHTYELLOW_EX)
                    continue
                else:
                    log_message("Maximum setup retries reached", Fore.LIGHTRED_EX)
                    return False
            else:
                log_message(f"Account setup failed with status {response.status_code}", Fore.LIGHTRED_EX)
                return False
        except Exception as e:
            log_message(f"Account setup failed: {str(e)}", Fore.LIGHTRED_EX)
            return False
    
    return False

def save_account(email, password, ref_code, access_token, refresh_token):
    try:
        with open("accounts.txt", "a") as f:
            f.write(f"Email: {email}\n")
            f.write(f"Password: {password}\n")
            f.write(f"Referrer Code: {ref_code}\n")
            f.write(f"Token: {access_token if access_token else 'null'}\n")
            f.write(f"Refresh Token: {refresh_token if refresh_token else 'null'}\n")
            f.write("-" * 50 + "\n")
        log_message("Account saved to accounts.txt", Fore.LIGHTMAGENTA_EX)
    except Exception as e:
        log_message(f"Failed to save account: {str(e)}", Fore.LIGHTRED_EX)

def main():
    global CURRENT_ACCOUNT, TOTAL_ACCOUNTS
    
    banner = f"""
{Fore.LIGHTCYAN_EX}╔═══════════════════════════════════════════╗
║        Liqfinity.com Autoreferral         ║
║          Without Captcha Solver           ║
║       https://github.com/im-hanzou        ║
╚═══════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)
    
    while True:
        ref_code = input(f"{Fore.LIGHTCYAN_EX}Enter referral code: {Style.RESET_ALL}").strip()
        if ref_code:
            break
        print(f"{Fore.LIGHTRED_EX}Referrer code cannot be empty{Style.RESET_ALL}")

    while True:
        user_input = input(f"{Fore.LIGHTCYAN_EX}Enter how many accounts: {Style.RESET_ALL}")
        if user_input.strip():
            try:
                TOTAL_ACCOUNTS = int(user_input)
                if TOTAL_ACCOUNTS > 0:
                    break
                else:
                    print(f"{Fore.LIGHTRED_EX}Total accounts cannot be zero or negative{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.LIGHTRED_EX}Please enter a valid number{Style.RESET_ALL}")
        else:
            print(f"{Fore.LIGHTRED_EX}Input cannot be empty, please try again{Style.RESET_ALL}")
    
    proxy_manager = ProxyManager()
    
    successful = 0
    failed = 0
    
    for i in range(TOTAL_ACCOUNTS):
        CURRENT_ACCOUNT = i + 1
        log_message(f"Processing new account...", Fore.LIGHTYELLOW_EX)
        
        proxies = proxy_manager.get_random_proxy()
        email, password, user_ref_code = register_account(ref_code, proxies)
        
        if not email or not password:
            failed += 1
            log_message("Skipping to next account...", Fore.LIGHTRED_EX)
            continue 
        
        access_token, refresh_token = login_account(email, password, proxies)
        
        success = setup_account(access_token, proxies, email)
        save_account(email, password, user_ref_code, access_token, refresh_token)
        
        if success:
            successful += 1
        else:
            failed += 1
            
    log_message("\nAll Process Completed", show_progress=False)
    log_message(f"Total accounts: {TOTAL_ACCOUNTS}", show_progress=False)
    log_message(f"Successful: {successful}", Fore.LIGHTGREEN_EX, False)
    log_message(f"Failed: {failed}", Fore.LIGHTRED_EX, False)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_message("\nProcess interrupted by user", Fore.LIGHTYELLOW_EX, False)
    except Exception as e:
        log_message(f"\nFatal error: {str(e)}", Fore.LIGHTRED_EX, False)
