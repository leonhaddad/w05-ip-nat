Task 1: For /31 I treat both addresses as usable (RFC3021); for /32 only one address exists and it is both first and last usable. 10.20.30.70 matches 10.0.0.0/8, 10.20.0.0/16, 10.20.30.0/24, 10.20.30.64/26 — longest-prefix rule picks 10.20.30.64/26. If two entries share the same prefix length, the table keeps the first-added entry (lookup preserves first-seen for equal lengths).

Task 2: Created two labelled records and a placeholder DHCP capture; you must collect real `dhcp.pcapng` and fill `out/report.md` with the capture analysis (Discover source, lease time, etc.).

Task 3: Implemented a per-prefix-length hash table: lookup masks the address for each prefix length from 32→0 and does O(1) dict checks, so work is O(33) per lookup (bounded by address width). Memory stores a dict per prefix length proportional to number of entries.
