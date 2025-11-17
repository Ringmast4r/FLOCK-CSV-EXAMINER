<div align="center">

# FLOCK CSV EXAMINER

![Welcome](gifs/Welcome_Ringmaster.gif)

![Repo Size](https://img.shields.io/github/repo-size/Ringmast4r/FLOCK-CSV-EXAMINER)
![Visitors](https://visitor-badge.laobi.icu/badge?page_id=Ringmast4r.FLOCK-CSV-EXAMINER)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

**Drop wardriving CSVs. Find Flock Safety cameras.**

---

</div>

## Live Demo

**[https://ringmast4r.github.io/FLOCK-CSV-EXAMINER](https://ringmast4r.github.io/FLOCK-CSV-EXAMINER)**

---

## Run Locally

```bash
python server.py
```

Open **http://localhost:2600**

---

## Features

- Drag & drop CSV files or folders (recursive scanning)
- Parallel processing (uses all CPU cores)
- Interactive map with 10 tile layer options
- Complete installation detection (clusters Battery + Camera within radius)
- FS Ext Battery SSID filter to eliminate false positives
- Adjustable cluster radius (10m - 200m)
- Export to CSV, GeoJSON, KML, SVG
- Google Maps pin drop links for each device
- Add/remove/customize OUI prefixes with localStorage persistence
- No external dependencies

---

## How It Works

1. Get your wardriving data from [WiGLE-Vault](https://github.com/Ringmast4r/WiGLE-Vault)
2. Drop your CSVs here
3. See potential detected Flock devices on map
4. Export results

---

<div align="center">

*Ringmast4r*

</div>
