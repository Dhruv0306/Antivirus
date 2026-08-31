This folder is staging only, it does not get merged into `main`. It exists so the wiki content can be reviewed as a normal PR diff before it goes anywhere.

I don't have push access to `Dhruv0306/Antivirus.wiki.git` (GitHub wikis are a separate git repo, and I only have a local clone of `main`, no credentials to push anywhere). Here's how to publish these pages once you're happy with them:

```bash
# 1. Enable the wiki if you haven't already: repo Settings > Features > Wikis.
#    Create at least one page through the GitHub UI first (even a blank
#    "Home" page); the wiki repo doesn't exist as a clonable git remote
#    until it has a first page.

# 2. Clone the wiki repo (separate from the main repo)
git clone https://github.com/Dhruv0306/Antivirus.wiki.git

# 3. Copy the staged pages in (from this repo's wiki-staging/ folder, on
#    this branch, not from main)
cp wiki-staging/Home.md \
   wiki-staging/Architecture.md \
   wiki-staging/Getting-Started.md \
   wiki-staging/Scanning-and-Verdicts.md \
   wiki-staging/Security-Model.md \
   wiki-staging/Testing.md \
   wiki-staging/Deployment.md \
   Antivirus.wiki/

# 4. Commit and push
cd Antivirus.wiki
git add .
git commit -m "docs: add architecture, setup, security, testing, and deployment pages"
git push

# 5. Once pushed, delete wiki-staging/ from main (this folder's only job
#    was getting the content to you for review)
```

After this, the wiki is its own git repo going forward. Future edits happen there directly, or in a future PR here that regenerates this same staging folder.
