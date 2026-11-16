# SBOM+ batch p10_classification

- projects: 10 (errors 0) - components 2478 - vulnerabilities 1292 {'LOW': 93, 'MEDIUM': 471, 'HIGH': 567, 'CRITICAL': 147, 'UNKNOWN': 14}
- license resolved rate: 0.99 - by source {'deps.dev': 1757, 'lockfile': 634, 'registry:npm': 41, 'registry:pypi': 16, 'registry:maven': 4}
- plans verified clean: 339 of 348 - patch: {'projects_patched': 10, 'projects_with_plans': 7, 'projects_applied': 7, 'vulns_before': 1291, 'rescan_fixed': 515, 'estimated_fixed': 705, 'rescan_fix_rate': 0.399, 'stop_reasons': {'applied': 5, 'regression_reverted': 1, 'nothing_applied': 4}}
- avg analysis: 47.1s - proposals: {'exaone': 0, 'deterministic': 10}

| project | components | vulns | license | plans clean | patch | arch edges | proposals |
|---|---|---|---|---|---|---|---|
| nodegoat | 1091 | 311 | 0.985 | 121/125 | applied | 34 | deterministic |
| nodejs-goof | 980 | 315 | 0.998 | 131/134 | regression_reverted | 6 | deterministic |
| pygoat | 58 | 369 | 1.0 | 34/34 | applied | 42 | deterministic |
| railsgoat | 167 | 114 | 0.994 | 22/22 | applied | 25 | deterministic |
| java-sec-code | 53 | 160 | 0.868 | 26/28 | nothing_applied | 46 | deterministic |
| gin | 32 | 8 | 1.0 | 2/2 | applied | 15 | deterministic |
| ripgrep | 69 | 0 | 1.0 | 0/0 | nothing_applied | 70 | deterministic |
| flask | 20 | 14 | 1.0 | 3/3 | applied | 175 | deterministic |
| express | 8 | 1 | 1.0 | 0/0 | nothing_applied | 58 | deterministic |
| iso14229 | 0 | 0 | None | 0/0 | nothing_applied | 83 | deterministic |
