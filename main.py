
"""
Script to scrape Mitre Webpage to correlate the following:
Threat Actors sheet
- TTPs for each Group
- Software for each Group

Software sheet
- TTPs for each Software
- Groups that use this software

Techniques sheet
- each Software
- each Group

Project start date: 12-15-2022

"""
import requests
from bs4 import BeautifulSoup
from operator import itemgetter


# Create functions to retrieve respective URLs for Mitre Groups and Software
def get_group_urls():  
# Retrieve the HTML from the Mitre webpage
    url = "https://attack.mitre.org/groups/"
    response = requests.get(url)

# Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')
    
# List each group from "Groups" page sidebar    
    Groups_sidebar = soup.findAll('div', class_='sidenav')
    
# Assign empty list to populate multiple dictionaries with "Threat Actor" and "url" keys.
    list_dicts_groups_and_urls = []

# Loop through all group names in Group sidebar
    for group in Groups_sidebar:
        list_dicts_groups_and_urls.append({"Threat Actor": group.a.text, "url": ("https://attack.mitre.org" + group.a['href'])}) 
    return list_dicts_groups_and_urls

# "reassign" global variable outside of pervious function
list_dicts_groups_and_urls = get_group_urls()


def get_groups_TTPs():
    results = []
    for group in list_dicts_groups_and_urls:
        url = group["url"]
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        #print(soup)
        # Find all of the tables on the page
#     for table in soup.find_all('table'):
#        print(table.get('class'))
        table = soup.findAll('table', class_='table techniques-used background table-bordered')
        #for row in table.tbody.findAll('tr'):
        for row in table.find_all('tr'):
            if 
            rows = row.findAll('td')
            return(rows)

print(get_groups_TTPs())











list_dicts_softwares_urls = []

def get_software_urls():
    # Retrieve the HTML from the Mitre webpage
    url = "https://attack.mitre.org/software/"
    response = requests.get(url)
    html = response.text

    # Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')

    softwares = soup.findAll('div', class_='sidenav')

    for item in softwares:
        list_dicts_softwares_urls.append({"Software": item.a.text, "url": ("https://attack.mitre.org" + item.a['href'])})

    return list_dicts_softwares_urls   

#Where do I put this 
urls = list(map(itemgetter('url'), list_dicts_softwares_urls))

def get_software_ttps():
    
    Software_Techniques=[]

    for url in urls:
        response = requests.get(url)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        Software_Techniques.append(url)
    
    return(Software_Techniques)

    # Iterate over each table and extract the ID and Name values
"""     for table in tables:
        h1 = table.find('h1')
        group_id = h1['id']
        group_name = h1.text
        print(f'ID: {group_id}, Name: {group_name}') """


"""           
        software_name = soup.findAll('div', class_='container_fluid')
        h1 = software_name.find('h1')
        Software_Techniques.append(h1)

"""

