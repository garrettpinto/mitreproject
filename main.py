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

results_exp = [
    {"ATP123": {"ttps": [], "software": []}},
    {"ATP129": {"ttps": [], "software": []}},
    {"ATP500": {"ttps": [], "software": []}}
]
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
        actor = group.div["id"].split("-")[0]
        url = group.a['href']
        if actor == "0":
            pass
        else:
            list_dicts_groups_and_urls.append({"Threat Actor": actor, "url": ("https://attack.mitre.org" + url)})
    return list_dicts_groups_and_urls

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



# list_dicts_groups_and_urls = get_group_urls()


# ttps = get_groups_info(list_dicts_groups_and_urls)


print()

def get_software_urls():
    # Retrieve the HTML from the Mitre webpage
    url = "https://attack.mitre.org/software/"
    response = requests.get(url)

    # Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # List each group from "Groups" page sidebar
    software_sidebar = soup.findAll('div', class_='sidenav')

    # Assign empty list to populate multiple dictionaries with "Threat Actor" and "url" keys.
    list_dicts_software_and_urls = []

    # Loop through all group names in Group sidebar...fix: ignore "side-nav-mobile-view"
    for software in software_sidebar:

        # # Check the id attribute of the div element
        # if group.div["class"] == "side-nav-desktop-view h-100":
        #     # Skip the rest of the loop iteration if the id is side-nav-mobile-view
        #     continue

            # "actor" variable that 'removes' duplication on Mitre page...need to fix for "Threat Group-, etc."
        software_name = software.div["id"].split("-")[0]
        # "url" variable that returns group url
        url = software.a['href']
        
        # skips "Overview" on sidebar and else continues through rest of sidebar list
        if software_name == "0":
            pass
        else:
            list_dicts_software_and_urls.append({"Software": software_name, "url": ("https://attack.mitre.org" + url)})
    
    return list_dicts_software_and_urls

def get_software_info(software_dict_list):
    
    software_results = []
    for dic in software_dict_list:

        url = dic["url"]
        actor = dic['Software']
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        tables = soup.findAll('table', class_='table')

        software_result_dict = {actor: {"ttps": [], "software": []}}

        for table in tables:

            if table['class'] == ['table', 'techniques-used', 'background', 'table-bordered']:
                ttps_list = software_result_dict[actor]["ttps"]
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
                software_list = software_result_dict[actor]["software"]
                trs = table.findAll('tr')
                for tr in trs:
                    tds = tr.findAll('td')
                    if len(tds) == 4:
                        software_list.append(tds[1].a.text + " (" + tds[0].a.text + ")")
                
            else:
                print("extra/unknown table")

        software_results.append(software_result_dict)
    

    return software_results


