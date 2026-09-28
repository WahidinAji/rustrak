---
"@rustrak/server": patch
---

Honor zero alert cooldown during same-second events and backward clock adjustments while preserving replay deduplication. Evaluate the current stored cooldown atomically so rule edits also apply to in-flight reservations.
