"""
Script to scrape Mitre Webpage to correlate the following:
Threat Actors sheet
- TTPs for each Group
- Software for each Group

Software sheet
- TTPs for each Software
- Groups that use this software

Project start date: 12-15-2022

"""
import requests
from bs4 import BeautifulSoup

# Create functions to retrieve respective URLs for Mitre Groups and Software
def get_group_urls():  
# Retrieve the HTML from the Mitre webpage
    url = "https://attack.mitre.org/groups/"
    response = requests.get(url)
    html = response.text

# Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    
    groups = soup.findAll('div', class_='sidenav')
    group_urls = []

    for item in groups:
        #group_urls.append("https://attack.mitre.org" + item.a['href'])
        group_urls.append({"Threat Actor": item.a.text, "url": ("https://attack.mitre.org" + item.a['href'])})

    return group_urls   

def get_software_urls():
    # Retrieve the HTML from the Mitre webpage
    url = "https://attack.mitre.org/software/"
    response = requests.get(url)
    html = response.text

    # Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')

    softwares = soup.findAll('div', class_='sidenav')
    
    softwares_urls = []

    for item in softwares:
        softwares_urls.append({"Software": item.a.text, "url": ("https://attack.mitre.org" + item.a['href'])})

    return softwares_urls   

def get_software_ttps():
    
    Software_Techniques=[]

    urls = get_software_urls()
    for url in urls:
        response = requests.get(url['url'])
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
#        Software_Techniques.append(url['url'])
        return(soup)

print(get_software_ttps())

"""    
    for url in urls:
        response = requests.get(url)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        
        software_name = soup.findAll('div', class_='container_fluid')
        h1 = software_name.find('h1')
        Software_Techniques.append(h1)
    
    return(Software_Techniques)

print(get_software_ttps())
"""

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
                
                A list of dictionaries, actor equals APT
                names will be rows
                values will be data
                """