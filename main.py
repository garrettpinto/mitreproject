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

# results_exp = [
#     {"APT123": {"ttps": [], "software": []}},
#     {"ATP129": {"ttps": [], "software": []}}
# ]

# Create function to retrieve respective URLs for Mitre Groups
def get_group_urls():
    # Retrieve the HTML from the Mitre webpage
    url = "https://attack.mitre.org/groups/"
    response = requests.get(url)

    # Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # List each group from "Groups" page sidebar
    groups_sidebar = soup.findAll('div', class_='sidenav')

    # Assign empty list to populate multiple dictionaries with "Threat Actor" and "url" keys.
    list_dicts_groups_and_urls = []

    # Loop through all group names in Group sidebar...fix: ignore "side-nav-mobile-view"
    for group in groups_sidebar:
        # "actor" variable that 'removes' duplication on Mitre page...need to fix for "Threat Group-, etc."
        actor = group.div["id"].split("-")[0]
        # "url" variable that returns group url
        url = group.a['href']
        
        # skips "Overview" on sidebar and else continues through rest of sidebar list
        if actor == "0":
            pass
        else:
            list_dicts_groups_and_urls.append({"Threat Actor": actor, "url": ("https://attack.mitre.org" + url)})
    
    return list_dicts_groups_and_urls

# Create function to populate results list with dictionaries containing ttps and software keys with their respective values
def get_groups_info(threat_actor_dict_list):
    
    results = []

    for dic in threat_actor_dict_list:

        url = dic["url"]
        actor = dic['Threat Actor']
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        tables = soup.findAll('table', class_='table')

        actor_result_dict = {actor: {"ttps": [], "software": []}}

        for table in tables:

            if table['class'] == ['table', 'techniques-used', 'background', 'table-bordered']:
                ttps_list = actor_result_dict[actor]["ttps"]
                trs = table.findAll('tr')
                for idx, tr in enumerate(trs):
                    tds = tr.findAll('td')
                    if len(tds) == 4:
                        ttps_list.append(tds[2].a.text + " (" + tds[1].a.text + ")")
                        
                    elif len(tds) == 5:
                        
                        try:
                            if len(tds[3].contents) > 2:
                                ttps_list.append((tds[3].contents[1].text + ": " + tds[3].contents[3].text) + " (" + (tds[1].a.text + tds[2].a.text) + ")")
                            else:
                                ttps_list.append(tds[3].a.text + " (" + (tds[1].a.text + tds[2].a.text) + ")")

                        except Exception as e:
                            # print(e)
                            for num in range(10):
                                try:
                                    old_tr = trs[idx - num]
                                    old_tds = old_tr.findAll('td')
                                    id1 = old_tds[1].a.text
                                    if len(tds[3].contents) > 3:
                                        ttps_list.append((tds[3].contents[1].text + ": " + tds[3].contents[3].text) + " (" + (id1 + tds[2].a.text) + ")")
                                    else:
                                        ttps_list.append(tds[3].a.text + " (" + (id1 + tds[2].a.text) + ")")
                                    break
                                except:
                                    pass

            elif table['class'] == ['table', 'table-bordered', 'table-alternate', 'mt-2']:
                software_list = actor_result_dict[actor]["software"]
                trs = table.findAll('tr')
                for tr in trs:
                    tds = tr.findAll('td')
                    if len(tds) == 4:
                        software_list.append(tds[1].a.text + " (" + tds[0].a.text + ")")
                
            else:
                print("extra/unknown table")

        results.append(actor_result_dict)
    

    return results


# Not needed??
list_dicts_groups_and_urls = get_group_urls()

# Whut
ttps = get_groups_info(list_dicts_groups_and_urls)


print()

#
# def get_software_urls():
#     # Retrieve the HTML from the Mitre webpage
#     url = "https://attack.mitre.org/software/"
#     response = requests.get(url)
#     html = response.text
#
#     # Parse the HTML using BeautifulSoup
#     soup = BeautifulSoup(html, 'html.parser')
#
#     softwares = soup.findAll('div', class_='sidenav')
#
#     for item in softwares:
#         list_dicts_softwares_urls.append({"Software": item.a.text, "url": ("https://attack.mitre.org" + item.a['href'])})
#
#     return list_dicts_softwares_urls
#
#
# def get_software_ttps():
#     Software_Techniques = []
#
#     for url in urls:
#         response = requests.get(url)
#         html = response.text
#         soup = BeautifulSoup(html, 'html.parser')
#         Software_Techniques.append(url)
#
#     return (Software_Techniques)
#
#     # Iterate over each table and extract the ID and Name values
#
#
# """     for table in tables:
#         h1 = table.find('h1')
#         group_id = h1['id']
#         group_name = h1.text
#         print(f'ID: {group_id}, Name: {group_name}') """
#
# """
#         software_name = soup.findAll('div', class_='container_fluid')
#         h1 = software_name.find('h1')
#         Software_Techniques.append(h1)
#
# """
#
