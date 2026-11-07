# PROMPTS.md — How I used AI on TrustVault

**Project:** TrustVault, a secure web platform for sharing confidential documents, with per-document permissions and an audit trail of who opened what and when.
**Student:** [YOUR NAME] · **Course / assessment:** [COURSE NAME]
**AI tool:** Claude (Anthropic), used in the claude.ai chat. Period covered: 4–7 November 2026.
**Other tools:** Supabase (database, authentication, storage), GitHub (private repository `docvault`), Netlify (hosting at `docvault-trust.netlify.app`).

> Lines marked **[ADD]** are for facts only I know (for example my own test results). Everything else is taken from my chat with the AI.

---

## 1. How I worked with the AI

1. **I decided what the product should do; the AI wrote the code.** The roles, the rules and the screens came from my requests. The AI produced the HTML, JavaScript and SQL.
2. **I asked for one feature at a time** and checked each result before the next request. The log in section 3 shows the order.
3. **I corrected the AI whenever the result was not what I meant**, whether it was a design, a behaviour or a wrong guess about my words (section 4).
4. **I kept the security rules in the database, not the browser.** The AI explained why. A hidden button can be bypassed, so rules such as "only the admin can approve an upload" have to be enforced in the SQL functions. I uploaded my real `supabase-schema.sql` so it could write patches against my actual code instead of guessing.
5. **I kept secrets out of the repository** after the AI explained the difference between the public anon key and the private `service_role` key. I also kept the repository private.

---

## 2. Files the AI helped produce

| File | Purpose |
|------|---------|
| `index.html` | The whole web app (login, documents, upload, admin, profile, help) |
| `supabase-schema.sql`, `patch-tv_edit.sql` | Original database and a fix for saving edits |
| `patch-upload-approval.sql` | Admin approves uploads; admin can see and edit every document |
| `patch-public-private.sql` | Public / Private access rules |
| `patch-delete-account.sql` | Owners and viewers can delete their own account |
| `patch-edit-profile.sql` | Change own name and username |
| `patch-role-requests.sql` | Help section: role change requests and admin notifications |
| `README.md`, `PROMPTS.md` | Documentation |

---

## 3. Prompt log (my words, unedited)

### Phase A — Interface and deployment
| # | My prompt | What the AI did |
|---|-----------|-----------------|
| 1 | "I want to remove extra register and sign in symbols in login page" | Read my file, found the duplicate Sign in / Register buttons, removed them and said it had guessed the meaning |
| 2 | "can't you make it more animative" | Added motion (rotating border, shimmer, reveal on scroll) |
| 3 | "how can mw web pages make faster in response" | Explained preconnect, parallel requests, indexes, lighter animations |
| 4 | "how can I upload in git repo" / "is step 1 safe" / "if I keep private" / "after can I change to public" | Steps for GitHub, private vs public, what to check before going public |
| 5 | "give me read me file" | Wrote `README.md` |
| 6 | (pasted the Netlify setup page) | Told me which build fields to leave empty |
| 7 | "after I make it public when I open the error is "Page not found…"" | Diagnosed that `index.html` must be at the top level of the repo |
| 8 | "how can I rename it in GitHub and netlify", "can I delete that published web site and deploy again then tell me steps" | Rename, move and redeploy steps |
| 9 | (pasted my GitHub file list) | Pointed out the file was still inside the folder `TrustVault-project 2` |
| 10 | "I don't understand" | Gave a shorter set of steps |
| 11 | "means html file should no be inside the `TrustVault-project 2`" / "how can I remove inside extra files" / "if the extra files inside is there a problem" | Confirmed, then explained that Netlify publishes every file in the repo, so SQL files would be readable once the site is public |

### Phase B — Features
| # | My prompt | What the AI did |
|---|-----------|-----------------|
| 12 | "in register page for password keep an eye icon to show password" | Added a show/hide icon on the password boxes |
| 13 | "why am I getting invalid credentials" | Explained that the page showed one message for every sign-in failure, and listed the real possible causes |
| 14 | "if any owner uploads a file the admin has to grant access so that the file can be uploaded" | Asked for my SQL schema, because the rules live in the database |
| 15 | "admin can also see and edit default" | Changed the plan so the admin can open documents, and added logging of admin access |
| 16 | "every document default access to admin to edit and if a owner upload a file the admin has to approve the upload then only the owner file can be uploaded" | Wrote `patch-upload-approval.sql` and the Pending / Approve / Reject screens |
| 17 | "I would like to add a section for selecting owners who can see or edit … can select several owners and also keep search bar to search owner" | Built the multi-select picker with search |
| 18 | "in admin page for every section keep limited space if more data … we can scroll in that limited space" | Fixed-height scrolling boxes with sticky headings |
| 19 | "in login page if a single credential is wrong then don't remove every detail in that and show that box with red and tell above" | Kept typed values, marked the wrong box red, moved the message above the form |
| 20 | "in owner page add a function of public or private. public-means every owner can have edit option and every viewer can have view option. private-means only selected owners can edit and selected viewers can view" | Wrote `patch-public-private.sql` and the Public / Private choice |
| 21 | "for owner and viewer to add an extra function at my name … profile user name and change password and delete account … if he tried to login it should show invalid credentials" | Profile page, password change, account deletion (`patch-delete-account.sql`) |
| 22 | "in my profile user name and name can change" | Added editing of name and username (`patch-edit-profile.sql`) |
| 23 | "add an another section called help for owner an viewer to change their role so that admin can approve it should show in notification" | Help section, role requests and a notification bell (`patch-role-requests.sql`) |
| 24 | "don't show notification on viewer and owner … in admin directly don't show role change requests if admin click in notification then click on review then show the role change" | Limited the bell to the admin and hid the request list until Review is clicked |

### Phase C — Visual design (several rounds)
| # | My prompt | What the AI did |
|---|-----------|-----------------|
| 25 | "I will give you reference try to make animations like this https://its-tomo.dev" | Read the site and added a vault-door intro, neon title, ticker, cursor ring |
| 26 | "no try like this https://macmillan.studio" | Second style (counter intro, smooth scroll, masked headings) |
| 27 | "don't take previous references and now do like this website templet … from index.html take only functionalities" | Rebuilt the look in a plain grey editorial style, keeping all features |
| 28 | "give me my previous website design as you given me for 2 days" | Restored an earlier design (see section 4, case 7) |
| 29 | "you first changed this website to another give me that 1" | Restored the first reference-based design |
| 30 | "change the circle to that protection logo" / "decrease size" | Replaced the cursor circle with the shield logo, then made it smaller |

---

## 4. Where the AI was wrong, or where I changed its direction

This is the evidence of directing the tool. "Caught by" says who noticed.

### Case 1 — One error message hid the real problem
- **What happened:** The sign-in code showed "Invalid credentials" for every failure, including a correct password on an account whose email was not yet confirmed.
- **Caught by:** me (I asked "why am I getting invalid credentials"); the AI then found the cause in the code.
- **Result:** I asked for better behaviour (prompt 19). Now the page shows a specific message (for example email not confirmed), keeps what I typed and marks the wrong box red.
- **Limit I accepted:** For a wrong email or wrong password the page still says "Email or password is incorrect" without saying which. Supabase does this deliberately so nobody can test whether an account exists.

### Case 2 — The eye icon behaved like a normal button
- **What happened:** The eye icon inherited the site-wide button effects: it lifted, scaled and glowed when hovered or clicked.
- **Caught by:** me ("don't do animation on eye icon").
- **Result:** The AI traced it to the shared button hover rules and overrode every state for that icon, and also stopped the neighbouring input from moving.

### Case 3 — The AI did not guess my database code
- **What happened:** My request needed changes inside the database functions. The AI did not invent them; it said it needed my real `supabase-schema.sql` and asked for it twice.
- **Directed by:** me (I uploaded the file), after the AI explained that rules in the browser alone can be bypassed.
- **Result:** The patches use my real function and table names.

### Case 4 — I overruled the AI's privacy rule
- **What happened:** The AI first planned for the admin to approve uploads by file name, owner and size only, because the original design said admins cannot read documents.
- **Caught by:** me ("admin can also see and edit default").
- **Result:** The admin can now see and edit every document. The AI pointed out the trade-off (any admin can read confidential files) and added logging of every admin open, download and edit so owners can see it.

### Case 5 — The deployment 404 and unclear steps
- **What happened:** The site showed "Page not found". The AI's first explanation was correct (the file must be at the top level), but my repo had the file inside a folder and the first instructions were confusing.
- **Caught by:** me ("I don't understand"); my pasted file list showed the real cause.
- **Result:** The AI gave shorter steps, and I uploaded `index.html` to the top level.

### Case 6 — The AI's own text became out of date
- **What happened:** After I changed the admin rule, the login page FAQ still said administrators cannot read documents, and the old sharing options were still described.
- **Caught by:** the AI, while editing later versions.
- **Result:** The FAQ, the Roles text and `README.md` were corrected so the site no longer contradicts itself.

### Case 7 — The AI misunderstood which design I wanted back
- **What happened:** I asked for my "previous design". The AI restored the earlier indigo-and-teal version. That was not the one I meant.
- **Caught by:** me ("you first changed this website to another give me that 1").
- **Result:** The AI restored the first reference-based version. It also saved the other versions under separate file names so nothing was lost.

### Case 8 — The AI could not see the reference website
- **What happened:** For the macmillan.studio request the AI could only read that site's text, not its layout or motion, so its first attempt was an interpretation. It said so.
- **Directed by:** me. I rejected the result twice (prompts 26–27) and finally told it to keep only the working features and take the style from the reference.
- **Result:** I decided which look to keep, and the AI restored it on request.

### Case 9 — Untested code
- **What happened:** In several replies the AI said it had checked the script for syntax errors but had not run the SQL or opened the page in a browser.
- **What I did:** I treated those replies as unverified until I tested them. **[ADD: which features you tested, on which dates, and what you found, for example "Registered a test viewer, sent a role request, approved it as admin; the bell count updated".]**

---

## 5. Decisions I made, not the AI

- The roles: administrator, document owner, viewer.
- Every upload needs admin approval before anyone else can see it.
- Public means every owner can edit and every viewer can view. Private means only the people I pick.
- Admins can see and edit every document, and every admin access is logged.
- Account deletion also deletes that owner's documents.
- The role-change notification goes to the admin only, and the request list opens only from the bell.
- Which visual style to keep, after trying three.

---

## 6. Checks I still need to do myself

- [ ] **[ADD]** Run all the SQL patches in order in a fresh Supabase project and confirm no errors.
- [ ] **[ADD]** Test each role (admin, owner, viewer) for upload, approval, Public and Private, profile changes, account deletion and role requests.
- [ ] **[ADD]** Confirm Row Level Security is on for every table and for the storage bucket.
- [ ] **[ADD]** Confirm no secret key (service_role or database password) is in the repository.

## 7. What I learned

- The AI works best when I ask for one change at a time and say exactly what I want to see.
- It can guess wrong about my meaning (the "extra symbols", the "previous design", the "circle"), so I read the summary of what it changed before accepting.
- Security rules need to live in the database, and anything the AI says it has not tested still needs my own test.
- **[ADD: one or two sentences in your own words.]**
