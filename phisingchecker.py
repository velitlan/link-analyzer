import requests
import base64

API_KEY = ''  #Zensiert

def encode_url(url):
    """Encodiert die URL in Base64."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')

def fetch_url_analysis(url_id):
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  #Ausnahme
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Fehler bei der Anfrage: {e}")
        return None

def analyze_url_data(data):
    if not data:
        print("\nKeine Daten für diese URL verfügbar.")
        return

    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    harmlos = stats.get('harmless', 0)
    sus = stats.get('suspicious', 0)
    mali = stats.get('malicious', 0)
    unent = stats.get('undetected', 0)

    if mali > 0:
        print("\nDie URL wurde als bösartig eingestuft!")
    elif sus > 0:
        print("\nDie URL zeigt verdächtige Merkmale.")
    elif harmlos > 0 and unent > 0:
        print("\nDie URL wird als harmlos eingestuft. Sie scheint sicher zu sein.")
    else:
        print("\nKeine ausreichenden Informationen zur URL.")

def main():
    url_to_check = input("Gib die zu prüfende URL ein:\n").strip()
    url_id = encode_url(url_to_check)
    data = fetch_url_analysis(url_id)
    analyze_url_data(data)

if __name__ == "__main__":
    main()
