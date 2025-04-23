import requests
import base64

API_KEY = 'PLATZHALTER'  #Zensiert
url_to_check = input("Gib die zu prüfende URL ein:\n").strip()

#URL base64-encodieren
url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip('=')

headers = {
    "x-apikey": API_KEY
}

#Analyse anfordern
response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

if response.status_code == 200:
    data = response.json()
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
        print("\nKeine Daten für diese URL verfügbar.")

else:
    print(f"Fehler bei der Anfrage: {response.status_code}")