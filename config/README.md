# Upstream synchronization

Run `node scripts/sync-upstreams.mjs --check` to preview a synchronization, or add `--apply` to update tracked source files.

`upstreams.json` defines source feeds, their managed blocks, and owner precedence from highest to lowest. A lower-priority domain rule is removed when a prior owner completely covers it; broader partially-overlapping rules are also removed when `strictIsolation` is enabled. This keeps the dedicated rule sets authoritative.

The Loyalsoldier source is pinned in `state/upstreams.lock.json`. `category-ads-all.txt` is imported into the managed block in `src/rj.list`; `geolocation-!cn.txt` is imported into `src/pr.list`. `gfwlist.txt` is decoded only to verify that it represents the same domain and regex inputs. Upstream regex rules remain quarantined: a regex change stops the sync for manual review.

`removalReports` records rules removed from a lower-priority owner. The dedicated service sets plus `ft`, `rj`, and `pr` are higher priority than `di`, so the synchronizer removes covered `di` rules and writes their overlap details to the configured Markdown report.
