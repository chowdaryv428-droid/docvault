# TrustVault on Supabase: setup

## 1. Create the project
1. Create a project at supabase.com.
2. **SQL Editor**: paste all of `supabase-schema.sql` and run it. It creates the tables, the access-rule functions, the hash-chained audit log, the private `vault` storage bucket and its policies.
3. **Project Settings > API**: copy the Project URL and the `anon` public key.

## 2. Configure the app
Open `TrustVault-supabase.html` and replace the two constants at the top of the first script:

```js
const SUPABASE_URL='https://xxxx.supabase.co';
const SUPABASE_ANON_KEY='eyJ...';   // anon key only, never service_role
```
Serve the file from any static host (or open it locally).

## 3. Auth settings (Authentication > Providers/Settings)
- Email provider on. Set minimum password length to 8.
- "Confirm email" is optional. If on, people confirm their email and then wait for admin approval.
- Add your site's URL under URL Configuration.

## 4. Create the first administrator
Administrators cannot self-register.
1. Register normally in the app (any role).
2. In the SQL editor run:
   ```sql
   update public.tv_profiles set role='admin', approved=true where username='your-username';
   ```
3. Sign in; approve everyone else from the Administration tab.

## How the rules are enforced
- Tables have Row Level Security with no policies, so browsers cannot read or write them directly. Everything goes through `tv_*` functions that re-check account status, role and grant on each call, and log refused attempts.
- Files sit in a private bucket. A file is released only to someone with access, and only within two minutes of the READ/DOWNLOAD audit entry being written.
- The audit log is append-only (triggers block update/delete/truncate) and hash-chained; "Verify audit chain" recomputes it in the database.

## Known limits
- File content checks (real PDF/PNG, UTF-8, valid JSON) run in the browser; the database cannot read file bytes. It does enforce name, extension, size (1 MB), bucket MIME types, ownership and category. For strict content checks add a Storage-triggered Edge Function.
- Wrong-password attempts are handled by Supabase Auth and are not in the TrustVault audit log (successful and denied sign-ins after authentication are).
- `tv_username_free` is callable without sign-in so registration can report taken usernames; it reveals whether a username exists.
- If a browser closes mid-save, an orphaned file can remain in Storage; clean the `vault` bucket periodically.
- I could not run the SQL against a live Postgres here; the JavaScript passed a syntax check. Run the schema in a fresh project first and tell me about any error it reports.
