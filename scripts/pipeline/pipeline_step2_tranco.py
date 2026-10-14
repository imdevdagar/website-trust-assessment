"""
pipeline_step2_tranco.py
=========================
Step 2: Download Tranco Top 1M list and add top legitimate domains
        as label=0 to balance the dataset.

Tranco is a research-grade list of the most popular domains,
combining Alexa, Majestic, Umbrella, and Quantcast rankings.
Official site: https://tranco-list.eu
"""
import sys, io, zipfile, requests
from pathlib import Path
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from src.features.url_features import extract_url_features

BASE       = Path(__file__).resolve().parent
CLEAN_CSV  = BASE / "data" / "processed" / "unified_clean.csv"
OUTPUT_CSV = BASE / "data" / "processed" / "unified_with_tranco.csv"
TRANCO_RAW = BASE / "data" / "raw" / "tranco_top1m.csv"

# How many top domains to pull and use for training
# Top 100k = extremely well-established, definitively legitimate
TOP_N = 100_000

print("=" * 60)
print("STEP 2: Tranco Top 1M — Legitimate Domain Expansion")
print("=" * 60)

# ── Download Tranco list ────────────────────────────────────────────────────
if not TRANCO_RAW.exists():
    print("\nDownloading Tranco Top 1M list...")
    TRANCO_URLS = [
        "https://tranco-list.eu/top-1m.csv.zip",
        "https://downloads.majestic.com/majestic_million.csv",
    ]
    downloaded = False
    for url in TRANCO_URLS:
        try:
            print(f"  Trying: {url}")
            r = requests.get(url, timeout=90, stream=True)
            r.raise_for_status()
            content = b"".join(r.iter_content(65536))
            # Try zip first
            try:
                z = zipfile.ZipFile(io.BytesIO(content))
                fname = z.namelist()[0]
                with z.open(fname) as f:
                    tranco_df = pd.read_csv(f, header=None, names=["rank", "domain"])
            except Exception:
                # Plain CSV fallback (e.g. Majestic)
                import io as _io
                tranco_df = pd.read_csv(
                    _io.StringIO(content.decode("utf-8", errors="replace")),
                    usecols=[0, 2], header=0
                )
                tranco_df.columns = ["rank", "domain"]
            tranco_df.to_csv(TRANCO_RAW, index=False)
            print(f"  Downloaded {len(tranco_df):,} domains")
            downloaded = True
            break
        except Exception as e:
            print(f"  Failed: {e}")

    if not downloaded:
        print("All downloads failed. Using built-in seed list of 500 well-known sites...")
        seed_domains = [
            "google.com","youtube.com","facebook.com","twitter.com","instagram.com",
            "wikipedia.org","reddit.com","amazon.com","linkedin.com","microsoft.com",
            "apple.com","netflix.com","github.com","stackoverflow.com","adobe.com",
            "wordpress.com","medium.com","pinterest.com","tumblr.com","shopify.com",
            "dropbox.com","paypal.com","ebay.com","airbnb.com","uber.com",
            "spotify.com","twitch.tv","discord.com","slack.com","zoom.us",
            "nytimes.com","bbc.com","cnn.com","theguardian.com","reuters.com",
            "bloomberg.com","forbes.com","techcrunch.com","wired.com","engadget.com",
            "bing.com","yahoo.com","duckduckgo.com","cloudflare.com","akamai.com",
            "salesforce.com","oracle.com","ibm.com","intel.com","nvidia.com",
            "samsung.com","sony.com","lg.com","hp.com","dell.com",
            "target.com","walmart.com","bestbuy.com","costco.com","etsy.com",
            "tripadvisor.com","booking.com","expedia.com","hotels.com","airbnb.com",
            "harvard.edu","mit.edu","stanford.edu","oxford.ac.uk","cambridge.org",
            "nih.gov","nasa.gov","cdc.gov","fbi.gov","irs.gov",
            "python.org","nodejs.org","php.net","ruby-lang.org","rust-lang.org",
            "docker.com","kubernetes.io","aws.amazon.com","azure.microsoft.com","cloud.google.com",
            "gitlab.com","bitbucket.org","atlassian.com","jira.com","confluence.com",
        ]
        tranco_df = pd.DataFrame({"rank": range(1, len(seed_domains)+1), "domain": seed_domains})
        tranco_df.to_csv(TRANCO_RAW, index=False)
        print(f"  Using {len(tranco_df)} seed domains")

else:
    print(f"\nLoading cached Tranco list from {TRANCO_RAW}")
    tranco_df = pd.read_csv(TRANCO_RAW)
    print(f"Loaded {len(tranco_df)} domains")

# ── Take top N ─────────────────────────────────────────────────────────────
top_domains = tranco_df.head(TOP_N)["domain"].tolist()
print(f"\nUsing top {len(top_domains)} domains for Legitimate expansion")

# ── Extract URL features ────────────────────────────────────────────────────
print("\nExtracting URL features for Tranco domains...")
feat_rows = []
skipped = 0
for i, domain in enumerate(top_domains):
    if i % 10000 == 0:
        print(f"  {i}/{len(top_domains)}...")
    url = "https://" + domain
    try:
        feats = extract_url_features(url)
        feats["label"] = 0   # Legitimate
        feat_rows.append(feats)
    except Exception:
        skipped += 1

tranco_feat_df = pd.DataFrame(feat_rows)
print(f"Extracted: {len(tranco_feat_df)} | Skipped: {skipped}")

# ── Merge with cleaned dataset ──────────────────────────────────────────────
if CLEAN_CSV.exists():
    print(f"\nLoading cleaned dataset: {CLEAN_CSV}")
    existing = pd.read_csv(CLEAN_CSV)
    print(f"  Existing shape: {existing.shape}")
    print(f"  Existing labels:\n{existing['label'].value_counts().to_string()}")

    tranco_aligned = tranco_feat_df.reindex(columns=existing.columns, fill_value=0)
    merged = pd.concat([existing, tranco_aligned], ignore_index=True)
else:
    merged = tranco_feat_df

# Final dedup on feature vectors
feat_cols = [c for c in merged.columns if c != 'label']
before = len(merged)
merged = merged.drop_duplicates(subset=feat_cols, keep='first')
print(f"Post-merge dedup: removed {before - len(merged)} rows")

merged.to_csv(OUTPUT_CSV, index=False)
print(f"\nExpanded dataset saved: {OUTPUT_CSV}")
print(f"Shape: {merged.shape}")
print(f"\nFinal label distribution:")
print(merged["label"].value_counts().to_string())
print(f"\n  Legitimate: {(merged['label']==0).sum():,}")
print(f"  Phishing:   {(merged['label']==1).sum():,}")
print(f"  Scam:       {(merged['label']==2).sum():,}")
print("\nDone!")
