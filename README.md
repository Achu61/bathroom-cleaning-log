# Bathroom Cleaning Log

Free, open-source app to record bathroom cleaning with QR codes.

- One **unique QR code per bathroom** (46 bathrooms included; edit the list in `server.js`).
- Staff sign in with their own **ID and password**, scan the code, and press **Cleaned** or **Not cleaned**.
- **Date and time are recorded automatically** by the server (staff cannot change them).
- **Admin** sees all entries (filter by date, bathroom, staff, status), the latest status of every bathroom, can add or remove staff, reset passwords, export CSV, and print the QR codes.

## Run it (free)

Requires [Node.js](https://nodejs.org) 18 or newer.

```bash
npm install
npm start
```

Open http://localhost:3000. The first person to open it creates the **admin** account.
Data is stored in `data/app.db` (SQLite). Back this folder up.

### Use it in the hospital (recommended, no cost, data stays on site)

1. Run it on any PC or small server that is always on and connected to the hospital Wi-Fi/LAN.
2. Staff phones open `http://<PC-IP-ADDRESS>:3000` (for example `http://192.168.1.20:3000`).
3. In the admin **QR codes** tab, set the app link to that address, press **Update codes**, and print.

### Free cloud hosting

GitHub only stores the code; **GitHub Pages cannot run this app** because it needs a server and a database.
To host it online for free you can use Render, Railway or Fly.io. Note that free plans may reset the disk, which would erase `data/app.db`; attach a persistent disk/volume and set `DATA_DIR` to it.

## Settings (environment variables)

| Name | Purpose |
|------|---------|
| `PORT` | Port number (default 3000) |
| `DATA_DIR` | Folder for the database (default `./data`) |
| `SECRET` | Secret for login cookies (generated automatically if not set) |
| `COOKIE_SECURE` | Set to `1` when serving over HTTPS |

## Security notes

Passwords are stored hashed (bcrypt) and logins are rate-limited. Use HTTPS if the app is reachable from the internet, and keep `data/` out of Git (already in `.gitignore`).

## License

MIT
