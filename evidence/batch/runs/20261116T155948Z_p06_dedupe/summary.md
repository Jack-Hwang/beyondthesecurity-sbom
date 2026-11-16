# SBOM+ batch p06_dedupe

- projects: 10 (errors 0) - components 2529 - vulnerabilities 1438 {'LOW': 189, 'MEDIUM': 511, 'HIGH': 576, 'CRITICAL': 146, 'UNKNOWN': 16}
- license resolved rate: 0.978 - by source {'deps.dev': 1778, 'lockfile': 634, 'registry:npm': 41, 'registry:pypi': 16, 'registry:maven': 4}
- plans verified clean: 357 of 366 - patch: {'projects_patched': 10, 'projects_with_plans': 7, 'projects_applied': 7, 'vulns_before': 1437, 'rescan_fixed': 507, 'estimated_fixed': 706, 'rescan_fix_rate': 0.353, 'stop_reasons': {'applied': 5, 'regression_reverted': 1, 'nothing_applied': 4}}
- avg analysis: 47.4s - proposals: {'exaone': 0, 'deterministic': 10}

| project | components | vulns | license | plans clean | patch | arch edges | proposals |
|---|---|---|---|---|---|---|---|
| nodegoat | 1091 | 311 | 0.985 | 121/125 | applied | 34 | deterministic |
| nodejs-goof | 980 | 315 | 0.998 | 131/134 | regression_reverted | 6 | deterministic |
| pygoat | 58 | 369 | 1.0 | 34/34 | applied | 42 | deterministic |
| railsgoat | 197 | 258 | 0.843 | 38/38 | applied | 0 | deterministic |
| java-sec-code | 53 | 160 | 0.868 | 26/28 | nothing_applied | 46 | deterministic |
| gin | 53 | 10 | 1.0 | 4/4 | applied | 15 | deterministic |
| ripgrep | 69 | 0 | 1.0 | 0/0 | nothing_applied | 70 | deterministic |
| flask | 20 | 14 | 1.0 | 3/3 | applied | 175 | deterministic |
| express | 8 | 1 | 1.0 | 0/0 | nothing_applied | 58 | deterministic |
| iso14229 | 0 | 0 | None | 0/0 | nothing_applied | 83 | deterministic |
