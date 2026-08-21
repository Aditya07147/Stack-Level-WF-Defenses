import os

SITE_SPECS = {
    "site1": [("index.html", 50 * 1024)],
    "site2": [("index.html", 120 * 1024)],
    "site3": [("index.html", 250 * 1024)],
    "site4": [(f"img{i}.jpg", (70 + i * 20) * 1024) for i in range(1, 6)],
    "site5": [(f"data{i}.bin", (80 + i * 15) * 1024) for i in range(1, 11)],
    "site6": [("index.html", 80 * 1024)],
    "site7": [("index.html", 180 * 1024)],
    "site8": [("index.html", 320 * 1024)],
    "site9": [("index.html", 450 * 1024)],
    "site10": [("index.html", 600 * 1024)],
}

def generate_sites(base_dir=None):
    if base_dir is None:
        base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sites")

    print(f"[*] Generating mock website assets in: {base_dir}")
    os.makedirs(base_dir, exist_ok=True)

    for site, files in SITE_SPECS.items():
        site_dir = os.path.join(base_dir, site)
        os.makedirs(site_dir, exist_ok=True)
        for filename, size_bytes in files:
            file_path = os.path.join(site_dir, filename)
            # Create content with a recognizable header and repeating filler
            header = f"<!-- Mock {site}/{filename} - Target Size: {size_bytes} bytes -->\n".encode('utf-8')
            filler_len = max(0, size_bytes - len(header))
            # Pseudo-random but deterministic pattern
            pattern = (f"{site}-{filename}-padding-block-").encode('utf-8')
            repeats = filler_len // len(pattern) + 1
            content = header + (pattern * repeats)[:filler_len]
            with open(file_path, "wb") as f:
                f.write(content)
            print(f"  [+] Created {site}/{filename} ({len(content)} bytes)")

    print("[*] Site asset generation complete.")

if __name__ == "__main__":
    generate_sites()
