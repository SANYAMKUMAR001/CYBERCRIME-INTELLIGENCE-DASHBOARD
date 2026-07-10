# GCF Cyber Crime Intelligence Platform

A safe, static, browser-only cybersecurity academic project for Google Cybersecurity Foundation presentations.

## Overview

This project simulates a Security Operations Center workflow using:

- HTML5
- CSS3
- Vanilla JavaScript
- Chart.js
- Local JSON demo data

It is designed for classroom demonstrations, threat intelligence practice, and incident response storytelling. It does not include any offensive security capability.

## Folder Structure

```text
GCF-CyberCrimeIntelligence/
  index.html
  dashboard.html
  investigation.html
  reports.html
  css/
  js/
  data/
  images/
  icons/
  README.md
```

## Features

- Premium landing page with SOC-style navigation
- Live dashboard with KPI cards, charts, threat feed, CVE explorer, and threat map
- Investigation simulator with workflow animation and IOC lookup
- Printable report page for academic presentation
- Local JSON data for safe offline demonstration

## How to Run

1. Open the `GCF-CyberCrimeIntelligence` folder in VS Code.
2. Use Live Server on `index.html`.
3. Navigate through the dashboard, investigation, and reports pages.

## Notes

- The datasets are synthetic and stored locally in `data/`.
- The platform is educational only and does not perform real attacks, scanning, exploitation, phishing, brute force, or malware behavior.
- If Chart.js fails to load from the CDN in an offline environment, download Chart.js locally and point the script tag to a local copy.
