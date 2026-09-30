---
"@rustrak/server": patch
---

Users can change their password from account settings, through `POST /auth/me/password` and `auth.changePassword()` in `@rustrak/client`. An alert rule with a zero or negative cooldown now fires every time, and the cooldown is checked against the rule's current value (@jav-ed).
