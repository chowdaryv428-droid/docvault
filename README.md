# 🔐 TrustVault

A secure web platform for sharing confidential documents. Every document has its own permissions, and every action is written to a tamper-evident audit trail showing who did what and when.

## Features

- **Role-based access:** administrator, document owner and viewer, each with clear limits.
- **Public or private documents:** *Public* means every owner can edit and every viewer can view. *Private* means only the owners you pick can edit and only the viewers you pick can view.
- **Private storage:** files sit in a private bucket and are released only to people who have access.
- **Audit trail:** opens, downloads, edits, permission changes and refused attempts are all logged.
- **Tamper-evident log:** the log is hash-chained, and an administrator can verify that no entry was altered.
- **My profile:** click your name to change your name, username and password, or (owners and viewers) delete your account. Deleting an account also deletes the documents that owner uploaded, and the person can no longer sign in.
- **Account approval:** new registrations must be approved by an administrator before they can sign in.
- **Upload approval:** every owner upload waits as *Pending* until an administrator approves it. Pending uploads are visible only to the owner and the administrator; rejected uploads are deleted from storage.
- **Instant control:** taking access back takes effect immediately.

## Roles

| Role | Can do |
|------|--------|
| Administrator | Approve or reject accounts and uploads, change roles, deactivate accounts, view the activity log, and see, open, download and edit every document by default (each access is written to the audit trail). Cannot upload or delete documents. |
| Document owner | Upload documents, mark them Public or Private, choose who can edit or view private ones, take access back, delete own documents. Can edit every public document. |
| Viewer | See and download every public document and the private documents shared with them. |

## Allowed files

`txt`, `md`, `csv`, `json`, `pdf` and `png`, up to 1 MB each. File content is checked against its type. Text files can be edited in the app.

## Tech stack

- Plain HTML, CSS and JavaScript in a single `index.html`
- [Supabase](https://supabase.com) for authentication, database and storage
- Security rules enforced in the database (Row Level Security and `tv_*` functions), not in the browser

## Getting started

1. Create a free project at [supabase.com](https://supabase.com).
2. Run these in the Supabase SQL editor, in this order: `supabase-schema.sql` (tables, functions and the private `vault` storage bucket), then `patch-tv_edit.sql`, then `patch-upload-approval.sql`, then `patch-public-private.sql`, then `patch-delete-account.sql`, then `patch-edit-profile.sql`.
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
| `patch-tv_edit.sql` | Fix for saving edited documents |
| `patch-upload-approval.sql` | Upload approval and default admin access (run after the two files above) |
| `patch-public-private.sql` | Public / Private access rules |
| `patch-delete-account.sql` | Lets owners and viewers delete their own account |
| `patch-edit-profile.sql` | Lets people change their own name and username (run last) |
| `SUPABASE_SETUP.md` | Step-by-step Supabase setup |

## License

Add a license of your choice, for example MIT, before making the repository public.
