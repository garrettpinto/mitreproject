def get_software_ttps():
    Software_Techniques=[]
    for url in get_software_urls():
        software_name = 
        return()


"""
def get_software_ttps():
    
    Software_Techniques={}
    
    for url in get_software_urls():
        response = requests.get(url)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        
        software_name = soup.findAll('div', class_='container_fluid')
        h1 = software_name.find('h1')
        Software_Techniques.append(h1)
    return(Software_Techniques)
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



18:04 last attempt

        software_name = soup.findAll('div', class_='container_fluid')
        h1 = software_name.find('h1')
        Software_Techniques.append(h1)

    return(Software_Techniques)