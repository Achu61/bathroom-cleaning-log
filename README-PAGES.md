# Bathroom Cleaning Log: free GitHub Pages + Supabase version

1. Supabase: SQL Editor -> New query -> paste `supabase-setup.sql` -> Run.
2. Supabase: Project Settings -> API Keys -> copy the PUBLIC key (publishable / anon).
   Paste it into `docs/config.js`. Never use the secret / service_role key.
3. Put `docs/` and `supabase-setup.sql` in your repository, then `git add . && git commit -m "Pages version" && git push`.
4. GitHub: repository Settings -> Pages -> Deploy from a branch -> `main` and folder `/docs` -> Save.
5. Open https://YOUR-USERNAME.github.io/bathroom-cleaning-log/ , create the admin, add staff, then print the QR codes from the QR tab.
