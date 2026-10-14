import requests
from bs4 import BeautifulSoup
import time
import pandas as pd
from pathlib import Path

urls = set()  # Use set to avoid duplicates
print("Starting DEEP scrape of AA419 Fake Banks Database (500 pages)...")

# Scrape 500 pages (20 records per page = up to 10,000 scam URLs)
for start in range(1, 10001, 20):
    page_url = f"https://db.aa419.org/fakebankslist.php?start={start}"
    try:
        resp = requests.get(page_url, timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        tds = soup.find_all('td', class_='tddomain')
        for td in tds:
            a_tag = td.find('a')
            if a_tag and a_tag.text.strip().startswith('http'):
                urls.add(a_tag.text.strip())
        
        if start % 200 == 1:
            print(f"  Progress: page start={start}, unique URLs so far: {len(urls)}")
        
        time.sleep(0.3)  # Be polite to the server
    except Exception as e:
        print(f"  Error on start={start}: {e}")
        time.sleep(2)
        continue

# Save
out_dir = Path(r'd:\WEBSITE ASSESSMENT SYSTEM\Scam dataset')
df = pd.DataFrame({'URL': list(urls), 'label': 2})
out_path = out_dir / 'aa419_scam_urls.csv'
df.to_csv(out_path, index=False)
print(f"\nDone! Saved {len(urls)} unique AA419 Scam URLs to {out_path}")
