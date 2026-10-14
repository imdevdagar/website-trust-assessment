import requests
from bs4 import BeautifulSoup
import time
import pandas as pd
from pathlib import Path

urls = []
print("Starting scrape of AA419 Fake Banks Database...")

# Scrape first 50 pages (20 records per page = 1000 scam URLs)
for start in range(1, 1001, 20):
    page_url = f"https://db.aa419.org/fakebankslist.php?start={start}"
    try:
        resp = requests.get(page_url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Find all td with class tddomain
        tds = soup.find_all('td', class_='tddomain')
        for td in tds:
            a_tag = td.find('a')
            if a_tag and a_tag.text.startswith('http'):
                urls.append(a_tag.text.strip())
        
        print(f"Scraped start={start}, total so far: {len(urls)}")
        time.sleep(0.5)  # Be polite to the server
    except Exception as e:
        print(f"Error on start={start}: {e}")
        break

# Save to dataset
out_dir = Path(r'd:\WEBSITE ASSESSMENT SYSTEM\Scam dataset')
out_dir.mkdir(exist_ok=True)

df = pd.DataFrame({'URL': urls, 'label': 2}) # 2 = Scam
out_path = out_dir / 'aa419_scam_urls.csv'
df.to_csv(out_path, index=False)
print(f"Successfully saved {len(urls)} AA419 Scam URLs to {out_path}!")
