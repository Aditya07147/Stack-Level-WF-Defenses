import os

# Define the 10 sites and their specific file sizes (in bytes) to create unique fingerprints
SITE_SPECS = {
    "site1":  {"index.html": 150000},
    "site2":  {"index.html": 800000},
    "site3":  {"index.html": 2500000},
    "site4":  {f"img{i}.jpg": 300000 for i in range(1, 6)}, # 5 images, 300KB each
    "site5":  {f"data{i}.bin": 100000 for i in range(1, 11)}, # 10 files, 100KB each
    "site6":  {"index.html": 45000},
    "site7":  {"index.html": 1200000},
    "site8":  {"index.html": 350000},
    "site9":  {"index.html": 600000},
    "site10": {"index.html": 950000},
}

os.makedirs("sites", exist_ok=True)

for site, files in SITE_SPECS.items():
    site_dir = os.path.join("sites", site)
    os.makedirs(site_dir, exist_ok=True)
    for filename, size in files.items():
        filepath = os.path.join(site_dir, filename)
        with open(filepath, "wb") as f:
            f.write(os.urandom(size))
            
print("[✓] Successfully generated dummy sites for traffic fingerprinting.")