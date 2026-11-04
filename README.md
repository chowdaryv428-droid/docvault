# 🔐 TrustVault

A secure web platform for sharing confidential documents. Every document has its own permissions, and every action is written to a tamper-evident audit trail showing who did what and when.

## Features

- **Role-based access:** administrator, document owner and viewer, each with clear limits.
- **Per-document permissions:** share with everyone, or only with chosen people, with view or edit access.
- **Private storage:** files sit in a private bucket and are released only to people who have access.
- **Audit trail:** opens, downloads, edits, permission changes and refused attempts are all logged.
- **Tamper-evident log:** the log is hash-chained, and an administrator can verify that no entry was altered.
- **Account approval:** new registrations must be approved by an administrator before they can sign in.
- **Instant control:** taking access back takes effect immediately.

## Roles

| Role | Can do |
|------|--------|
| Administrator | Approve or reject accounts, change roles, deactivate accounts, view the document register and activity log. Cannot open document contents unless an owner shares one. |
| Document owner | Upload documents, choose who can view or edit, take access back, delete own documents. |
| Viewer | See and download documents shared with them. |

## Allowed files

`txt`, `md`, `csv`, `json`, `pdf` and `png`, up to 1 MB each. File content is checked against its type. Text files can be edited in the app.

## Tech stack

- Plain HTML, CSS and JavaScript in a single `index.html`
- [Supabase](https://supabase.com) for authentication, database and storage
- Security rules enforced in the database (Row Level Security and `tv_*` functions), not in the browser

## Getting started

1. Create a free project at [supabase.com](https://supabase.com).
2. Run `supabase-schema.sql` in the Supabase SQL editor to create the tables, functions and the private `vault` storage bucket.
3. In Supabase, go to **Project Settings → API** and copy the project URL and the public **anon** key.
4. Open `index.html` and fill in these two values at the top of the first script:
   ```js
   const SUPABASE_URL = 'https://YOUR-PROJECT.supabase.co';
   const SUPABASE_ANON_KEY = 'YOUR-ANON-KEY';
   ```
5. Open `index.html` in a browser, or publish it with Netlify, Vercel or GitHub Pages.
6. Create the first administrator as described in `SUPABASE_SETUP.md`.

## Security notes

- Use only the **anon** key in the page. **Never** put the `service_role` key, database password or any secret in this repository.
- Keep Row Level Security turned on for all tables and for the storage bucket.
- Turn on email confirmation in Supabase Authentication settings if you want verified emails.
- Administrator accounts cannot be self-registered.

## Project files

| File | Purpose |
|------|---------|
| `index.html` | The whole web app |
| `supabase-schema.sql` | Database tables, functions and security rules |
| `SUPABASE_SETUP.md` | Step-by-step Supabase setup |

## License

Add a license of your choice, for example MIT, before making the repository public.
