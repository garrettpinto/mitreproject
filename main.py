"""


"""
import requests
from bs4 import BeautifulSoup

# Create a function to get 
def get_groups():
    # Retrieve the HTML from the Mitre webpage
    url = "https://attack.mitre.org/groups/"
    response = requests.get(url)
    html = response.text

    # Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    
    groups = soup.findAll('div', class_='sidenav')
    group_urls = []

    for item in groups:
        group_urls.append("https://attack.mitre.org" + item.a['href'] )

    return group_urls   

def get_softwares():
    # Retrieve the HTML from the Mitre webpage
    url = "https://attack.mitre.org/software/"
    response = requests.get(url)
    html = response.text

    # Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    
    softwares = soup.findAll('div', class_='sidenav')
    softwares_urls = []

    for item in softwares:
        softwares_urls.append("https://attack.mitre.org" + item.a['href'] )

    return softwares_urls   

print(get_softwares() + get_groups())



""" 
results = []

For each URL, get page
        get T body
        T body: give me all "TRs"   
        for TR in list of TRs
            TDs = TR.findAll(TDs)
            if len(TDs) == 4:
                results.append([APT name, TDs [1].a.text, TDs[2].a.text)
            elif len(TDs) == 5
                results.append([APT name, (TDs [1].a.text + TDs[2].a.text), (TDs [3].children[0] + (TDs [3].children[1])))
                """
                
