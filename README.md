# Threatwire

A static cybersecurity news site. GitHub Actions collects headlines from open sources every hour and saves them to `data/news.json`; GitHub Pages serves `index.html`, which reads that file.

## Setup (about 5 minutes)

1. Create a new GitHub repository and upload everything in this folder, including the hidden `.github` folder.
2. Go to **Settings > Pages**, set Source to **Deploy from a branch**, pick `main` and `/ (root)`, then save.
3. Go to **Settings > Actions > General > Workflow permissions** and choose **Read and write permissions**.
4. Open the **Actions** tab, select **Update news**, and click **Run workflow**. After it finishes, your site at `https://<username>.github.io/<repo>/` shows live items.

## Sources

Edit `RSS_SOURCES` in `scripts/fetch_news.py` to add or remove feeds. Other built-in sources: CISA Known Exploited Vulnerabilities, Have I Been Pwned breach list, and ransomware.live (metadata about leak-site claims).

## Dark web coverage

The site does not crawl Tor or host leaked data. It shows public metadata (group, victim organization, date) from trackers that monitor leak sites, and links out.

## Test the script locally

    python scripts/fetch_news.py
    python -m http.server 8000   # then open http://localhost:8000
