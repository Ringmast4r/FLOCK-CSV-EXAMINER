#!/usr/bin/env python3
"""
Ringmast4r FLOCK CSV Examiner
Wardriving CSV analyzer for Flock Safety surveillance device detection
"""

import http.server
import socketserver
import json
import csv
import io
import html
from urllib.parse import parse_qs, urlparse
import os

PORT = 2600

# Flock Safety OUI Database (IEEE-verified)
FLOCK_OUIS = {
    # Extended Battery Devices (Silicon Laboratories)
    "04:0D:84": "Extended Battery (Silicon Labs)",
    "1C:34:F1": "Extended Battery (Silicon Labs)",
    "38:5B:44": "Extended Battery (Silicon Labs)",
    "58:8E:81": "Extended Battery (Silicon Labs)",
    "90:35:EA": "Extended Battery (Silicon Labs)",
    "94:34:69": "Extended Battery (Silicon Labs)",
    "B4:E3:F9": "Extended Battery (Silicon Labs)",
    "CC:CC:CC": "Extended Battery (Silicon Labs)",
    "EC:1B:BD": "Extended Battery (Silicon Labs)",
    "F0:82:C0": "Extended Battery (Silicon Labs)",
    # WiFi Camera Devices (Liteon Technology)
    "70:C9:4E": "WiFi Camera (Liteon)",
    "3C:91:80": "WiFi Camera (Liteon)",
    "D8:F3:BC": "WiFi Camera (Liteon)",
    "80:30:49": "WiFi Camera (Liteon)",
    "14:5A:FC": "WiFi Camera (Liteon)",
    "74:4C:A1": "WiFi Camera (Liteon)",
    "08:3A:88": "WiFi Camera (Liteon)",
    "9C:2F:9D": "WiFi Camera (Liteon)",
    "94:08:53": "WiFi Camera (Liteon)",
    "E4:AA:EA": "WiFi Camera (Liteon)",
    "00:F4:8D": "WiFi Camera (Liteon)",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Ringmast4r Flock Hunter</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect x='10' y='60' width='80' height='10' fill='%23ff0000'/><rect x='25' y='25' width='50' height='35' fill='%23ff0000'/></svg>">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            margin: 0;
            padding: 20px 40px;
            background: #0d1117;
            color: #c9d1d9;
        }
        h1 { color: #ff0000; }
        h2 { color: #8b949e; margin-top: 30px; }
        .upload-area {
            border: 2px dashed #30363d;
            padding: 40px;
            text-align: center;
            margin: 20px 0;
            border-radius: 8px;
            background: #161b22;
        }
        .upload-area:hover { border-color: #ff0000; }
        input[type="file"] {
            padding: 10px;
            background: #21262d;
            border: 1px solid #30363d;
            color: #c9d1d9;
            border-radius: 6px;
        }
        button {
            background: #238636;
            color: white;
            padding: 10px 24px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            margin: 10px;
        }
        button:hover { background: #2ea043; }
        button.secondary {
            background: #21262d;
            border: 1px solid #30363d;
        }
        button.secondary:hover { background: #30363d; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: #161b22;
            border-radius: 8px;
            overflow: hidden;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #21262d;
        }
        th {
            background: #21262d;
            color: #ff0000;
            font-weight: 600;
        }
        th.sortable {
            cursor: pointer;
        }
        th.sortable:hover {
            background: #30363d;
        }
        th.sortable::after {
            content: ' \\2195';
            opacity: 0.5;
        }
        tr:hover { background: #1c2128; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-box {
            background: #161b22;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #30363d;
        }
        .stat-number {
            font-size: 32px;
            font-weight: bold;
            color: #ff0000;
        }
        .stat-label { color: #8b949e; margin-top: 5px; }
        .alert {
            background: #f85149;
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        .warning {
            background: #d29922;
            color: #0d1117;
        }
        .success {
            background: #238636;
        }
        .device-type {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }
        .type-battery {
            background: #32cd32;
            color: #0d1117;
        }
        .type-camera {
            background: #58a6ff;
            color: #0d1117;
        }
        .type-custom {
            background: #8b949e;
            color: #0d1117;
        }
        .filter-controls {
            background: #161b22;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border: 1px solid #30363d;
        }
        .filter-controls input, .filter-controls select {
            padding: 8px;
            background: #0d1117;
            border: 1px solid #30363d;
            color: #c9d1d9;
            border-radius: 6px;
            margin: 5px;
        }
        .map-link {
            color: #ff0000;
            text-decoration: none;
        }
        .map-link:hover { text-decoration: underline; }
        .hacker-gif {
            max-width: 800px;
            width: 95%;
            margin: 10px auto;
            display: block;
            opacity: 0;
            transition: opacity 0.8s ease-in-out;
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
        }
        .hacker-gif.visible { opacity: 1; }
        .gif-container {
            position: relative;
            height: 450px;
            width: 100%;
        }
        #results { margin-top: 30px; }
        .hidden { display: none; }
        code {
            background: #21262d;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
        }
        .export-btn {
            background: #1f6feb;
        }
        .export-btn:hover { background: #388bfd; }
        #map {
            height: 500px;
            width: 100%;
            border-radius: 8px;
            margin: 20px 0;
            border: 1px solid #30363d;
        }
        .delete-btn {
            background: #da3633;
            color: white;
            border: none;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        .delete-btn:hover { background: #f85149; }
        .add-oui-form {
            background: #161b22;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border: 1px solid #30363d;
        }
        .add-oui-form input, .add-oui-form select {
            padding: 8px;
            background: #0d1117;
            border: 1px solid #30363d;
            color: #c9d1d9;
            border-radius: 6px;
            margin: 5px;
        }
        .add-oui-form button {
            background: #238636;
            margin: 5px;
        }
        .reset-btn {
            background: #6e7681;
        }
        .reset-btn:hover { background: #8b949e; }
    </style>
</head>
<body>
    <h1 style="color: #ff0000; margin-bottom: 20px;">RINGMAST4R FLOCK HUNTER</h1>

    <div class="upload-area" id="dropZone">
        <h3>Drop Wardriving Files or Folders Here</h3>
        <p style="color: #8b949e; margin: 10px 0;">CSV, KML, Kismet, NetStumbler, inSSIDer, WiFiFoFum, and more</p>
        <input type="file" id="fileInput" accept=".csv,.kml,.netxml,.kismet,.ns1,.txt" multiple webkitdirectory directory style="display:none">
        <input type="file" id="folderInput" webkitdirectory directory multiple style="display:none">
    </div>
    <button class="secondary" onclick="resetDropZone()" style="margin-bottom: 20px;">Reset / New Scan</button>

    <div id="results" class="hidden">
        <h2>Analysis Results</h2>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-number" id="totalNetworks">0</div>
                <div class="stat-label">Total Networks Scanned</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="flockDevices">0</div>
                <div class="stat-label">Flock Devices Found</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="batteryDevices">0</div>
                <div class="stat-label">Extended Battery Units</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="cameraDevices">0</div>
                <div class="stat-label">WiFi Camera Units</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="completeInstalls">0</div>
                <div class="stat-label">Complete Installations</div>
            </div>
        </div>

        <div id="alertBox"></div>

        <div id="installToggleContainer" style="margin: 15px 0; display: none;">
            <button id="installToggleBtn" onclick="toggleInstallationView()" style="background: #ff0000; color: #fff; border: none; padding: 12px 24px; font-size: 16px; font-weight: bold; cursor: pointer; border-radius: 5px;">
                SHOW COMPLETE INSTALLATIONS ONLY
            </button>
            <button id="fsFilterBtn" onclick="toggleFSFilter()" style="background: #ff6600; color: #fff; border: none; padding: 12px 24px; font-size: 16px; font-weight: bold; cursor: pointer; border-radius: 5px; margin-left: 10px; display: none;">
                FILTER: FS EXT BATTERY SSID ONLY
            </button>
            <span id="installRadiusControl" style="margin-left: 20px; display: none;">
                Cluster Radius: <input type="range" id="clusterRadius" min="10" max="200" value="50" oninput="updateClusterRadius()" style="vertical-align: middle;"> <span id="radiusValue">50m</span>
            </span>
        </div>

        <h2>Device Map</h2>
        <div id="map"></div>

        <div class="filter-controls">
            <strong>Filters:</strong>
            <select id="typeFilter" onchange="filterResults()">
                <option value="all">All Device Types</option>
                <option value="battery">Extended Battery Only</option>
                <option value="camera">WiFi Camera Only</option>
            </select>
            <input type="text" id="searchFilter" placeholder="Search MAC/SSID..." oninput="filterResults()">
            <button class="export-btn" onclick="exportCSV()">Export CSV</button>
            <button class="export-btn" onclick="exportGeoJSON()">Export GeoJSON</button>
            <button class="export-btn" onclick="exportKML()">Export KML</button>
            <button class="export-btn" onclick="exportMapSVG()">Export Map SVG</button>
            <button class="secondary" onclick="resetDropZone()">New Scan</button>
        </div>

        <table id="resultsTable">
            <thead>
                <tr>
                    <th class="sortable" onclick="sortResults('mac')">MAC Address</th>
                    <th class="sortable" onclick="sortResults('ssid')">SSID</th>
                    <th class="sortable" onclick="sortResults('deviceType')">Device Type</th>
                    <th class="sortable" onclick="sortResults('rssi')">Signal (dBm)</th>
                    <th class="sortable" onclick="sortResults('channel')">Channel</th>
                    <th class="sortable" onclick="sortResults('lat')">Latitude</th>
                    <th class="sortable" onclick="sortResults('lon')">Longitude</th>
                    <th class="sortable" onclick="sortResults('firstSeen')">First Seen</th>
                    <th>Map</th>
                </tr>
            </thead>
            <tbody id="resultsBody"></tbody>
        </table>
    </div>

    <h2>Flock Safety OUI Reference <span id="ouiCount" style="color: #8b949e; font-size: 16px;"></span></h2>
    <button class="secondary" onclick="toggleEditMode()" id="editToggleBtn">Edit OUIs</button>

    <div class="add-oui-form hidden" id="ouiEditForm">
        <strong>Add Custom OUI:</strong><br>
        <input type="text" id="newOuiPrefix" placeholder="XX:XX:XX" maxlength="8" style="width: 100px;">
        <select id="newOuiType" onchange="toggleCustomType()">
            <option value="battery">Extended Battery</option>
            <option value="camera">WiFi Camera</option>
            <option value="custom">Custom Type</option>
        </select>
        <input type="text" id="newOuiCustomType" placeholder="Custom Type Name" style="width: 150px; display: none;">
        <input type="text" id="newOuiManufacturer" placeholder="Manufacturer" style="width: 200px;">
        <button onclick="addCustomOUI()">Add OUI</button>
        <button class="reset-btn" onclick="resetToDefaults()">Reset to Defaults</button>
    </div>

    <table id="ouiTable">
        <thead>
            <tr>
                <th>OUI Prefix</th>
                <th>Device Type</th>
                <th>Manufacturer</th>
                <th class="action-col hidden">Action</th>
            </tr>
        </thead>
        <tbody id="ouiTableBody">
        </tbody>
    </table>

    <script>
        const DEFAULT_FLOCK_OUIS = {
            "04:0D:84": "Extended Battery (Silicon Labs)",
            "1C:34:F1": "Extended Battery (Silicon Labs)",
            "38:5B:44": "Extended Battery (Silicon Labs)",
            "58:8E:81": "Extended Battery (Silicon Labs)",
            "90:35:EA": "Extended Battery (Silicon Labs)",
            "94:34:69": "Extended Battery (Silicon Labs)",
            "B4:E3:F9": "Extended Battery (Silicon Labs)",
            "CC:CC:CC": "Extended Battery (Silicon Labs)",
            "EC:1B:BD": "Extended Battery (Silicon Labs)",
            "F0:82:C0": "Extended Battery (Silicon Labs)",
            "70:C9:4E": "WiFi Camera (Liteon)",
            "3C:91:80": "WiFi Camera (Liteon)",
            "D8:F3:BC": "WiFi Camera (Liteon)",
            "80:30:49": "WiFi Camera (Liteon)",
            "14:5A:FC": "WiFi Camera (Liteon)",
            "74:4C:A1": "WiFi Camera (Liteon)",
            "08:3A:88": "WiFi Camera (Liteon)",
            "9C:2F:9D": "WiFi Camera (Liteon)",
            "94:08:53": "WiFi Camera (Liteon)",
            "E4:AA:EA": "WiFi Camera (Liteon)",
            "00:F4:8D": "WiFi Camera (Liteon)"
        };

        // Load from localStorage or use defaults
        let FLOCK_OUIS = JSON.parse(localStorage.getItem('flock_ouis')) || {...DEFAULT_FLOCK_OUIS};

        let allResults = [];
        let filteredResults = [];
        let totalNetworksCount = 0;
        let map = null;
        let markersLayer = null;
        let workers = [];
        let editMode = false;
        let sortColumn = null;
        let sortAsc = true;
        let clusterMode = false;
        let clusterRadius = 50; // meters
        let installations = [];
        let fsFilterMode = false;

        // Create worker code as blob for parallel processing
        function createWorkerCode() {
            return `
            const FLOCK_OUIS = ${JSON.stringify(FLOCK_OUIS)};

            function getOUIPrefix(mac) {
                const normalized = mac.toUpperCase().replace(/[^A-F0-9]/g, '').substring(0, 6);
                if (normalized.length >= 6) {
                    return normalized.substring(0,2) + ':' + normalized.substring(2,4) + ':' + normalized.substring(4,6);
                }
                return mac.toUpperCase().substring(0, 8);
            }

            function isFlockDevice(mac) {
                return FLOCK_OUIS.hasOwnProperty(getOUIPrefix(mac));
            }

            function getDeviceType(mac) {
                return FLOCK_OUIS[getOUIPrefix(mac)] || "Unknown";
            }

            function parseCSV(text) {
                const lines = text.split(String.fromCharCode(10));
                const results = [];
                let networkCount = 0;

                let dataStartIndex = 0;
                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i].trim();
                    if (line === '' || line.startsWith('#') || line.toLowerCase().startsWith('wiglewifi')) continue;
                    if (line.toLowerCase().includes('mac') || line.toLowerCase().includes('bssid')) {
                        dataStartIndex = i;
                        break;
                    }
                }

                if (dataStartIndex >= lines.length) return { results: [], networkCount: 0 };

                const headers = lines[dataStartIndex].split(',').map(h => h.trim().toLowerCase().replace(/ /g, '').replace(/_/g, '').replace(/-/g, ''));
                const macIdx = headers.findIndex(h => h === 'mac' || h === 'bssid' || h === 'netid' || h === 'macaddress' || h === 'ap' || h === 'apmac' || h === 'address');
                const ssidIdx = headers.findIndex(h => h === 'ssid' || h === 'name' || h === 'essid' || h === 'networkname' || h === 'apname');
                const rssiIdx = headers.findIndex(h => h === 'rssi' || h === 'signal' || h === 'bestlevel' || h === 'level' || h === 'signalstrength' || h === 'dbm' || h === 'maxsignal' || h === 'minsignal');
                const channelIdx = headers.findIndex(h => h === 'channel' || h === 'chan' || h === 'ch');
                const latIdx = headers.findIndex(h => h === 'trilat' || h === 'bestlat' || h === 'lat' || h === 'latitude' || h === 'currentlatitude' || h === 'gpslat' || h === 'gpslatitude' || h === 'n' || h === 'y');
                const lonIdx = headers.findIndex(h => h === 'trilong' || h === 'bestlon' || h === 'lon' || h === 'longitude' || h === 'currentlongitude' || h === 'gpslon' || h === 'gpslongitude' || h === 'long' || h === 'lng' || h === 'e' || h === 'x');
                const timeIdx = headers.findIndex(h => h === 'firsttime' || h === 'firstseen' || h === 'time' || h === 'lastseen' || h === 'lasttime' || h === 'date' || h === 'datetime' || h === 'timestamp');

                if (macIdx === -1) return { results: [], networkCount: 0 };

                for (let i = dataStartIndex + 1; i < lines.length; i++) {
                    const line = lines[i].trim();
                    if (line === '' || line.startsWith('#')) continue;
                    networkCount++;

                    const cols = [];
                    let current = '';
                    let inQuotes = false;
                    for (let c of line) {
                        if (c === '"') inQuotes = !inQuotes;
                        else if (c === ',' && !inQuotes) { cols.push(current.trim()); current = ''; }
                        else current += c;
                    }
                    cols.push(current.trim());

                    if (cols.length <= macIdx) continue;
                    const mac = cols[macIdx] || '';
                    if (mac && isFlockDevice(mac)) {
                        results.push({
                            mac: mac,
                            ssid: ssidIdx >= 0 ? (cols[ssidIdx] || 'N/A') : 'N/A',
                            deviceType: getDeviceType(mac),
                            rssi: rssiIdx >= 0 ? (cols[rssiIdx] || 'N/A') : 'N/A',
                            channel: channelIdx >= 0 ? (cols[channelIdx] || 'N/A') : 'N/A',
                            lat: latIdx >= 0 ? (cols[latIdx] || 'N/A') : 'N/A',
                            lon: lonIdx >= 0 ? (cols[lonIdx] || 'N/A') : 'N/A',
                            firstSeen: timeIdx >= 0 ? (cols[timeIdx] || 'N/A') : 'N/A'
                        });
                    }
                }
                return { results, networkCount };
            }

            self.onmessage = function(e) {
                const result = parseCSV(e.data.text);
                self.postMessage({ id: e.data.id, ...result });
            };
        `;
        }

        const numWorkers = navigator.hardwareConcurrency || 4;
        let workerUrl = null;

        function initWorkers() {
            // Terminate existing workers
            workers.forEach(w => w.terminate());
            workers = [];
            if (workerUrl) URL.revokeObjectURL(workerUrl);

            const workerBlob = new Blob([createWorkerCode()], { type: 'application/javascript' });
            workerUrl = URL.createObjectURL(workerBlob);
            for (let i = 0; i < numWorkers; i++) {
                workers.push(new Worker(workerUrl));
            }
        }

        initWorkers();

        // GIF rotation (excludes Welcome_Ringmaster and jason bourne which plays first)
        const gifList = [
            'gifs/Animation%20GIF.gif',
            'gifs/Hacking%20Hacker%20Man%20GIF%20by%20PERFECTL00P.gif',
            'gifs/jim%20carrey%20coffee%20GIF.gif',
            'gifs/paper%20draft%20GIF.gif',
            'gifs/Working%20Jim%20Carrey%20GIF.gif'
        ];
        let shuffledGifs = [];
        let gifIndex = 0;
        let gifInterval = null;
        let preloadedGifs = [];
        let currentGifElement = 0;

        // Preload all GIFs
        gifList.forEach(src => {
            const img = new Image();
            img.src = src;
            preloadedGifs.push(img);
        });

        function shuffleArray(arr) {
            const a = [...arr];
            for (let i = a.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [a[i], a[j]] = [a[j], a[i]];
            }
            return a;
        }

        function getNextGif() {
            if (gifIndex >= shuffledGifs.length) {
                shuffledGifs = shuffleArray(gifList);
                gifIndex = 0;
            }
            return shuffledGifs[gifIndex++];
        }

        function crossfadeGif() {
            const gif1 = document.getElementById('hackerGif1');
            const gif2 = document.getElementById('hackerGif2');
            if (!gif1 || !gif2) return;

            const nextSrc = getNextGif();
            if (currentGifElement === 0) {
                gif2.src = nextSrc;
                gif1.classList.remove('visible');
                gif2.classList.add('visible');
                currentGifElement = 1;
            } else {
                gif1.src = nextSrc;
                gif2.classList.remove('visible');
                gif1.classList.add('visible');
                currentGifElement = 0;
            }
        }

        // Drag and drop setup
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');

        dropZone.addEventListener('click', () => fileInput.click());

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#58a6ff';
            dropZone.style.background = '#1c2128';
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.style.borderColor = '#30363d';
            dropZone.style.background = '#161b22';
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#30363d';
            dropZone.style.background = '#161b22';
            handleDrop(e.dataTransfer.items);
        });

        fileInput.addEventListener('change', (e) => {
            processFiles(Array.from(e.target.files));
        });

        async function handleDrop(items) {
            const files = [];
            const entries = [];

            for (let item of items) {
                if (item.webkitGetAsEntry) {
                    entries.push(item.webkitGetAsEntry());
                }
            }

            await getAllFiles(entries, files);
            processFiles(files);
        }

        async function getAllFiles(entries, files) {
            for (let entry of entries) {
                if (entry.isFile) {
                    const name = entry.name.toLowerCase();
                    if (name.endsWith('.csv') || name.endsWith('.netxml') || name.endsWith('.kismet') ||
                        name.endsWith('.kml') || name.endsWith('.ns1') || name.endsWith('.txt') ||
                        name.endsWith('.tsv') || name.endsWith('.log') || name.endsWith('.xml')) {
                        const file = await new Promise(resolve => entry.file(resolve));
                        files.push(file);
                    }
                } else if (entry.isDirectory) {
                    const reader = entry.createReader();
                    let allEntries = [];
                    // readEntries may not return all entries at once, need to loop
                    const readAll = async () => {
                        const batch = await new Promise(resolve => reader.readEntries(resolve));
                        if (batch.length > 0) {
                            allEntries = allEntries.concat(batch);
                            await readAll();
                        }
                    };
                    await readAll();
                    await getAllFiles(allEntries, files);
                }
            }
        }

        function processFiles(files) {
            if (files.length === 0) {
                alert('No wardriving files found (CSV, KML, Kismet, etc.)');
                return;
            }

            allResults = [];
            totalNetworksCount = 0;
            let filesProcessed = 0;
            let workerIndex = 0;
            let fileQueue = [...files];
            let activeWorkers = 0;
            const startTime = performance.now();

            shuffledGifs = shuffleArray(gifList);
            gifIndex = 0;
            currentGifElement = 0;
            const firstGif = 'gifs/jason%20bourne%20GIF.gif';
            const secondGif = getNextGif();
            dropZone.innerHTML = '<h3>Processing ' + files.length + ' CSV file(s) with ' + numWorkers + ' parallel workers...</h3><div class="gif-container"><img src="' + firstGif + '" class="hacker-gif visible" id="hackerGif1"><img src="' + secondGif + '" class="hacker-gif" id="hackerGif2"></div><p style="color: #8b949e;" id="progressText">0 / ' + files.length + ' files</p>';

            // Rotate GIFs every 3 seconds with crossfade
            gifInterval = setInterval(crossfadeGif, 3000);

            function updateProgress() {
                const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
                const progressText = document.getElementById('progressText');
                if (progressText) {
                    progressText.textContent = filesProcessed + ' / ' + files.length + ' files (' + elapsed + 's)';
                }
            }

            function processNext(worker) {
                if (fileQueue.length === 0) {
                    activeWorkers--;
                    if (activeWorkers === 0) {
                        if (gifInterval) clearInterval(gifInterval);
                        const totalTime = ((performance.now() - startTime) / 1000).toFixed(2);
                        displayResults(totalNetworksCount);
                        dropZone.innerHTML = '<h3>Drop Wardriving CSV Files or Folders Here</h3><p style="color: #8b949e; margin: 10px 0;">Processed ' + files.length + ' files in ' + totalTime + 's</p>';
                    }
                    return;
                }

                const file = fileQueue.shift();
                const reader = new FileReader();
                reader.onload = function(e) {
                    worker.postMessage({ id: file.name, text: e.target.result });
                };
                reader.readAsText(file);
            }

            // Setup worker handlers
            workers.forEach(worker => {
                worker.onmessage = function(e) {
                    allResults = allResults.concat(e.data.results);
                    totalNetworksCount += e.data.networkCount;
                    filesProcessed++;
                    updateProgress();
                    processNext(worker);
                };
                activeWorkers++;
                processNext(worker);
            });
        }

        function normalizeMAC(mac) {
            return mac.toUpperCase().replace(/[^A-F0-9]/g, '').substring(0, 6);
        }

        function getOUIPrefix(mac) {
            const normalized = normalizeMAC(mac);
            if (normalized.length >= 6) {
                return normalized.substring(0,2) + ':' + normalized.substring(2,4) + ':' + normalized.substring(4,6);
            }
            return mac.toUpperCase().substring(0, 8);
        }

        function isFlockDevice(mac) {
            const prefix = getOUIPrefix(mac);
            return FLOCK_OUIS.hasOwnProperty(prefix);
        }

        function getDeviceType(mac) {
            const prefix = getOUIPrefix(mac);
            return FLOCK_OUIS[prefix] || "Unknown";
        }

        function parseWiGLECSV(text) {
            const lines = text.split('\\n');
            const results = [];

            // Skip WiGLE header comments and metadata lines
            let dataStartIndex = 0;
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                // Skip empty lines, comments, and WiGLE metadata lines
                if (line === '' || line.startsWith('#') || line.toLowerCase().startsWith('wiglewifi')) {
                    continue;
                }
                // Found a line that looks like a header (contains MAC or BSSID)
                if (line.toLowerCase().includes('mac') || line.toLowerCase().includes('bssid')) {
                    dataStartIndex = i;
                    break;
                }
            }

            if (dataStartIndex >= lines.length) return results;

            // Parse CSV header
            const headerLine = lines[dataStartIndex];
            const headers = headerLine.split(',').map(h => h.trim().toLowerCase());

            // Find column indices
            const macIdx = headers.findIndex(h => h === 'mac' || h === 'bssid' || h === 'netid');
            const ssidIdx = headers.findIndex(h => h === 'ssid' || h === 'name');
            const rssiIdx = headers.findIndex(h => h === 'rssi' || h === 'signal' || h === 'bestlevel');
            const channelIdx = headers.findIndex(h => h === 'channel');
            const latIdx = headers.findIndex(h => h === 'trilat' || h === 'bestlat' || h === 'lat' || h === 'latitude' || h === 'currentlatitude');
            const lonIdx = headers.findIndex(h => h === 'trilong' || h === 'bestlon' || h === 'lon' || h === 'longitude' || h === 'currentlongitude');
            const timeIdx = headers.findIndex(h => h === 'firsttime' || h === 'firstseen' || h === 'time');

            if (macIdx === -1) {
                console.error('Could not find MAC address column');
                return results;
            }

            // Parse data rows
            for (let i = dataStartIndex + 1; i < lines.length; i++) {
                const line = lines[i].trim();
                if (line === '' || line.startsWith('#')) continue;

                // Handle quoted CSV fields
                const cols = [];
                let current = '';
                let inQuotes = false;
                for (let c of line) {
                    if (c === '"') {
                        inQuotes = !inQuotes;
                    } else if (c === ',' && !inQuotes) {
                        cols.push(current.trim());
                        current = '';
                    } else {
                        current += c;
                    }
                }
                cols.push(current.trim());

                if (cols.length <= macIdx) continue;

                const mac = cols[macIdx] || '';
                if (mac && isFlockDevice(mac)) {
                    results.push({
                        mac: mac,
                        ssid: ssidIdx >= 0 ? (cols[ssidIdx] || 'N/A') : 'N/A',
                        deviceType: getDeviceType(mac),
                        rssi: rssiIdx >= 0 ? (cols[rssiIdx] || 'N/A') : 'N/A',
                        channel: channelIdx >= 0 ? (cols[channelIdx] || 'N/A') : 'N/A',
                        lat: latIdx >= 0 ? (cols[latIdx] || 'N/A') : 'N/A',
                        lon: lonIdx >= 0 ? (cols[lonIdx] || 'N/A') : 'N/A',
                        firstSeen: timeIdx >= 0 ? (cols[timeIdx] || 'N/A') : 'N/A'
                    });
                }
            }

            return results;
        }

        // Calculate distance between two coordinates in meters (Haversine formula)
        function getDistanceMeters(lat1, lon1, lat2, lon2) {
            const R = 6371000; // Earth radius in meters
            const dLat = (lat2 - lat1) * Math.PI / 180;
            const dLon = (lon2 - lon1) * Math.PI / 180;
            const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
                      Math.sin(dLon/2) * Math.sin(dLon/2);
            const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
            return R * c;
        }

        // Find complete installations (clusters of different device types)
        function findInstallations() {
            installations = [];
            const used = new Set();

            // Get devices with valid coordinates
            const devicesWithCoords = allResults.filter(r => {
                const lat = parseFloat(r.lat);
                const lon = parseFloat(r.lon);
                return !isNaN(lat) && !isNaN(lon) && lat !== 0 && lon !== 0;
            });

            // Group by device type category
            const getTypeCategory = (type) => {
                if (type.includes('Battery')) return 'battery';
                if (type.includes('Camera')) return 'camera';
                return 'custom';
            };

            // For each device, find nearby devices of different types
            for (let i = 0; i < devicesWithCoords.length; i++) {
                if (used.has(i)) continue;

                const device = devicesWithCoords[i];
                const lat1 = parseFloat(device.lat);
                const lon1 = parseFloat(device.lon);
                const type1 = getTypeCategory(device.deviceType);

                const cluster = [device];
                const clusterTypes = new Set([type1]);
                used.add(i);

                // Find nearby devices of different types
                for (let j = i + 1; j < devicesWithCoords.length; j++) {
                    if (used.has(j)) continue;

                    const other = devicesWithCoords[j];
                    const lat2 = parseFloat(other.lat);
                    const lon2 = parseFloat(other.lon);
                    const type2 = getTypeCategory(other.deviceType);

                    const distance = getDistanceMeters(lat1, lon1, lat2, lon2);

                    if (distance <= clusterRadius && !clusterTypes.has(type2)) {
                        cluster.push(other);
                        clusterTypes.add(type2);
                        used.add(j);
                    }
                }

                // Only count as installation if multiple device types found
                if (clusterTypes.size >= 2) {
                    installations.push({
                        devices: cluster,
                        types: Array.from(clusterTypes),
                        centerLat: lat1,
                        centerLon: lon1
                    });
                }
            }

            return installations;
        }

        function toggleInstallationView() {
            clusterMode = !clusterMode;
            const btn = document.getElementById('installToggleBtn');
            const radiusControl = document.getElementById('installRadiusControl');
            const fsFilterBtn = document.getElementById('fsFilterBtn');

            if (clusterMode) {
                btn.textContent = 'SHOW ALL DEVICES';
                btn.style.background = '#238636';
                radiusControl.style.display = 'inline';
                fsFilterBtn.style.display = 'inline-block';
                // Filter table to only show devices in installations
                filterToInstallations();
            } else {
                btn.textContent = 'SHOW COMPLETE INSTALLATIONS ONLY';
                btn.style.background = '#ff0000';
                radiusControl.style.display = 'none';
                fsFilterBtn.style.display = 'none';
                // Reset FS filter when going back to all devices
                fsFilterMode = false;
                fsFilterBtn.textContent = 'FILTER: FS EXT BATTERY SSID ONLY';
                fsFilterBtn.style.background = '#ff6600';
                // Restore to all results (respect any active filters)
                filterResults();
                updateAlertBox();
            }
            updateMapMarkers();
        }

        function toggleFSFilter() {
            fsFilterMode = !fsFilterMode;
            const btn = document.getElementById('fsFilterBtn');

            if (fsFilterMode) {
                btn.textContent = 'SHOW ALL INSTALLATIONS';
                btn.style.background = '#238636';
            } else {
                btn.textContent = 'FILTER: FS EXT BATTERY SSID ONLY';
                btn.style.background = '#ff6600';
            }

            filterToInstallations();
            updateMapMarkers();
            updateAlertBox();
        }

        function countFSInstallations() {
            return installations.filter(install =>
                install.devices.some(d =>
                    d.ssid.toLowerCase().includes('fs') ||
                    d.ssid.toLowerCase().includes('ext battery') ||
                    d.ssid.toLowerCase().includes('flock')
                )
            ).length;
        }

        function updateAlertBox() {
            const alertBox = document.getElementById('alertBox');
            if (allResults.length > 0) {
                let alertMsg = 'FLOCK SAFETY DEVICES DETECTED: ' + allResults.length + ' surveillance device(s) found in your scan data.';
                if (installations.length > 0) {
                    alertMsg += ' <strong>' + installations.length + ' complete installation(s)</strong> identified (multiple device types within ' + clusterRadius + 'm).';
                    if (fsFilterMode) {
                        const fsCount = countFSInstallations();
                        alertMsg += ' <strong style="color: #ffff00; background: #000; padding: 2px 6px; border-radius: 3px;">' + fsCount + ' confirmed FS installations</strong> (with FS/Ext Battery SSID).';
                    }
                }
                alertBox.innerHTML = '<div class="alert">' + alertMsg + '</div>';
            }
        }

        function filterToInstallations() {
            // Get all MACs that are part of installations
            const installationMACs = new Set();

            // If FS filter is on, only include installations that have "FS" or "Ext Battery" in SSID
            const relevantInstallations = fsFilterMode ?
                installations.filter(install =>
                    install.devices.some(d =>
                        d.ssid.toLowerCase().includes('fs') ||
                        d.ssid.toLowerCase().includes('ext battery') ||
                        d.ssid.toLowerCase().includes('flock')
                    )
                ) : installations;

            relevantInstallations.forEach(install => {
                install.devices.forEach(d => {
                    installationMACs.add(d.mac);
                });
            });

            // Filter to only devices in installations
            filteredResults = allResults.filter(r => installationMACs.has(r.mac));
            renderTable();
        }

        function updateClusterRadius() {
            clusterRadius = parseInt(document.getElementById('clusterRadius').value);
            document.getElementById('radiusValue').textContent = clusterRadius + 'm';
            findInstallations();
            document.getElementById('completeInstalls').textContent = installations.length;
            if (clusterMode) {
                filterToInstallations();
                updateMapMarkers();
                updateAlertBox();
            }
        }

        function displayResults(totalNetworks) {
            document.getElementById('results').classList.remove('hidden');
            document.getElementById('totalNetworks').textContent = totalNetworks.toLocaleString();
            document.getElementById('flockDevices').textContent = allResults.length;

            const batteryCount = allResults.filter(r => r.deviceType.includes('Battery')).length;
            const cameraCount = allResults.filter(r => r.deviceType.includes('Camera')).length;

            document.getElementById('batteryDevices').textContent = batteryCount;
            document.getElementById('cameraDevices').textContent = cameraCount;

            // Find complete installations
            findInstallations();
            document.getElementById('completeInstalls').textContent = installations.length;

            // Show installation toggle button if installations found
            const installToggleContainer = document.getElementById('installToggleContainer');
            if (installations.length > 0) {
                installToggleContainer.style.display = 'block';
            } else {
                installToggleContainer.style.display = 'none';
            }

            // Alert box
            const alertBox = document.getElementById('alertBox');
            if (allResults.length > 0) {
                let alertMsg = 'FLOCK SAFETY DEVICES DETECTED: ' + allResults.length + ' surveillance device(s) found in your scan data.';
                if (installations.length > 0) {
                    alertMsg += ' <strong>' + installations.length + ' complete installation(s)</strong> identified (multiple device types within ' + clusterRadius + 'm).';
                }
                alertBox.innerHTML = '<div class="alert">' + alertMsg + '</div>';
            } else {
                alertBox.innerHTML = '<div class="alert success">No Flock Safety devices detected in the uploaded data.</div>';
            }

            filteredResults = [...allResults];
            renderTable();
            initMap();
        }

        function initMap() {
            if (map) {
                map.remove();
            }

            map = L.map('map').setView([39.8283, -98.5795], 4);

            // All the map layers
            const layers = {
                'OpenStreetMap': L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap'
                }),
                'Satellite (ESRI)': L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
                    attribution: '© ESRI'
                }),
                'Terrain (OpenTopoMap)': L.tileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenTopoMap'
                }),
                'Dark Mode': L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                    attribution: '© CartoDB'
                }),
                'CartoDB Voyager': L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', {
                    attribution: '© CartoDB'
                }),
                'ESRI World Terrain': L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Terrain_Base/MapServer/tile/{z}/{y}/{x}', {
                    attribution: '© ESRI'
                }),
                'ESRI Shaded Relief': L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Shaded_Relief/MapServer/tile/{z}/{y}/{x}', {
                    attribution: '© ESRI'
                }),
                'CartoDB Positron': L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
                    attribution: '© CartoDB'
                }),
                'ESRI Topo': L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}', {
                    attribution: '© ESRI'
                }),
                'ESRI Streets': L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}', {
                    attribution: '© ESRI'
                })
            };

            layers['Dark Mode'].addTo(map);
            L.control.layers(layers).addTo(map);

            markersLayer = L.layerGroup().addTo(map);
            updateMapMarkers();
        }

        function updateMapMarkers() {
            if (!markersLayer) return;
            markersLayer.clearLayers();

            const bounds = [];

            // If cluster mode, show installations with highlight circles
            if (clusterMode && installations.length > 0) {
                // Filter installations if FS filter is on
                const displayInstallations = fsFilterMode ?
                    installations.filter(install =>
                        install.devices.some(d =>
                            d.ssid.toLowerCase().includes('fs') ||
                            d.ssid.toLowerCase().includes('ext battery') ||
                            d.ssid.toLowerCase().includes('flock')
                        )
                    ) : installations;

                displayInstallations.forEach((install, idx) => {
                    // Draw radius circle for installation
                    const circle = L.circle([install.centerLat, install.centerLon], {
                        radius: clusterRadius,
                        fillColor: '#ff0000',
                        color: '#ff0000',
                        weight: 3,
                        opacity: 0.8,
                        fillOpacity: 0.15
                    });

                    let popupContent = '<strong style="color: #ff0000;">COMPLETE INSTALLATION #' + (idx + 1) + '</strong><br>';
                    popupContent += '<strong>Types:</strong> ' + install.types.join(', ') + '<br>';
                    popupContent += '<strong>Devices:</strong> ' + install.devices.length + '<br><hr>';

                    install.devices.forEach(d => {
                        popupContent += '<strong>MAC:</strong> ' + d.mac + '<br>';
                        popupContent += '<strong>Type:</strong> ' + d.deviceType + '<br>';
                        popupContent += '<strong>SSID:</strong> ' + d.ssid + '<br><br>';
                    });

                    circle.bindPopup(popupContent);
                    markersLayer.addLayer(circle);

                    // Add individual device markers within installation
                    install.devices.forEach(r => {
                        const lat = parseFloat(r.lat);
                        const lon = parseFloat(r.lon);
                        bounds.push([lat, lon]);
                        let color;
                        if (r.deviceType.includes('Battery')) color = '#32cd32';
                        else if (r.deviceType.includes('Camera')) color = '#58a6ff';
                        else color = '#8b949e';
                        const marker = L.circleMarker([lat, lon], {
                            radius: 10,
                            fillColor: color,
                            color: '#ff0000',
                            weight: 3,
                            opacity: 1,
                            fillOpacity: 0.9
                        });
                        marker.bindPopup(
                            '<strong style="color: #ff0000;">PART OF INSTALLATION #' + (idx + 1) + '</strong><br>' +
                            '<strong>MAC:</strong> ' + r.mac + '<br>' +
                            '<strong>SSID:</strong> ' + r.ssid + '<br>' +
                            '<strong>Type:</strong> ' + r.deviceType + '<br>' +
                            '<strong>Signal:</strong> ' + r.rssi + ' dBm<br>' +
                            '<strong>First Seen:</strong> ' + r.firstSeen
                        );
                        markersLayer.addLayer(marker);
                    });
                });
            } else {
                // Normal mode - show all devices
                filteredResults.forEach(r => {
                    if (r.lat !== 'N/A' && r.lon !== 'N/A' && r.lat && r.lon) {
                        const lat = parseFloat(r.lat);
                        const lon = parseFloat(r.lon);
                        if (!isNaN(lat) && !isNaN(lon)) {
                            bounds.push([lat, lon]);
                            let color;
                            if (r.deviceType.includes('Battery')) color = '#32cd32';
                            else if (r.deviceType.includes('Camera')) color = '#58a6ff';
                            else color = '#8b949e';
                            const marker = L.circleMarker([lat, lon], {
                                radius: 10,
                                fillColor: color,
                                color: '#fff',
                                weight: 2,
                                opacity: 1,
                                fillOpacity: 0.8
                            });
                            marker.bindPopup(
                                '<strong>MAC:</strong> ' + r.mac + '<br>' +
                                '<strong>SSID:</strong> ' + r.ssid + '<br>' +
                                '<strong>Type:</strong> ' + r.deviceType + '<br>' +
                                '<strong>Signal:</strong> ' + r.rssi + ' dBm<br>' +
                                '<strong>First Seen:</strong> ' + r.firstSeen
                            );
                            markersLayer.addLayer(marker);
                        }
                    }
                });
            }

            if (bounds.length > 0) {
                map.fitBounds(bounds, { padding: [20, 20] });
            }
        }

        function filterResults() {
            const typeFilter = document.getElementById('typeFilter').value;
            const searchFilter = document.getElementById('searchFilter').value.toLowerCase();

            filteredResults = allResults.filter(r => {
                let typeMatch = true;
                if (typeFilter === 'battery') typeMatch = r.deviceType.includes('Battery');
                if (typeFilter === 'camera') typeMatch = r.deviceType.includes('Camera');

                let searchMatch = true;
                if (searchFilter) {
                    searchMatch = r.mac.toLowerCase().includes(searchFilter) ||
                                  r.ssid.toLowerCase().includes(searchFilter);
                }

                return typeMatch && searchMatch;
            });

            renderTable();
            updateMapMarkers();
        }

        function sortResults(column) {
            if (sortColumn === column) {
                sortAsc = !sortAsc;
            } else {
                sortColumn = column;
                sortAsc = true;
            }

            filteredResults.sort((a, b) => {
                let aVal = a[column];
                let bVal = b[column];

                // Handle numeric sorting
                if (column === 'rssi' || column === 'channel' || column === 'lat' || column === 'lon') {
                    aVal = parseFloat(aVal) || 0;
                    bVal = parseFloat(bVal) || 0;
                    return sortAsc ? aVal - bVal : bVal - aVal;
                }

                // String sorting
                aVal = String(aVal).toLowerCase();
                bVal = String(bVal).toLowerCase();
                if (aVal < bVal) return sortAsc ? -1 : 1;
                if (aVal > bVal) return sortAsc ? 1 : -1;
                return 0;
            });

            renderTable();
        }

        function renderTable() {
            const tbody = document.getElementById('resultsBody');
            tbody.innerHTML = '';

            for (let r of filteredResults) {
                const tr = document.createElement('tr');
                let typeClass, typeName;
                if (r.deviceType.includes('Battery')) {
                    typeClass = 'type-battery';
                    typeName = 'Extended Battery';
                } else if (r.deviceType.includes('Camera')) {
                    typeClass = 'type-camera';
                    typeName = 'WiFi Camera';
                } else {
                    typeClass = 'type-custom';
                    typeName = r.deviceType.includes('(') ? r.deviceType.split('(')[0].trim() : r.deviceType;
                }

                let mapLink = 'N/A';
                if (r.lat !== 'N/A' && r.lon !== 'N/A' && r.lat && r.lon) {
                    const lat = parseFloat(r.lat);
                    const lon = parseFloat(r.lon);
                    if (!isNaN(lat) && !isNaN(lon) && lat !== 0 && lon !== 0) {
                        // Use search query to drop a pin at exact coordinates
                        mapLink = '<a class="map-link" href="https://www.google.com/maps/search/?api=1&query=' + lat + ',' + lon + '" target="_blank">View</a>';
                    }
                }

                tr.innerHTML =
                    '<td><code>' + escapeHtml(r.mac) + '</code></td>' +
                    '<td>' + escapeHtml(r.ssid) + '</td>' +
                    '<td><span class="device-type ' + typeClass + '">' + typeName + '</span></td>' +
                    '<td>' + escapeHtml(r.rssi) + '</td>' +
                    '<td>' + escapeHtml(r.channel) + '</td>' +
                    '<td>' + escapeHtml(r.lat) + '</td>' +
                    '<td>' + escapeHtml(r.lon) + '</td>' +
                    '<td>' + escapeHtml(r.firstSeen) + '</td>' +
                    '<td>' + mapLink + '</td>';
                tbody.appendChild(tr);
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = String(text);
            return div.innerHTML;
        }

        function exportCSV() {
            if (filteredResults.length === 0) {
                alert('No results to export');
                return;
            }

            let csv = 'MAC,SSID,DeviceType,RSSI,Channel,Latitude,Longitude,FirstSeen\\n';
            for (let r of filteredResults) {
                csv += '"' + r.mac + '","' + r.ssid.replace(/"/g, '""') + '","' +
                       r.deviceType + '",' + r.rssi + ',' + r.channel + ',' +
                       r.lat + ',' + r.lon + ',"' + r.firstSeen + '"\\n';
            }

            downloadFile(csv, 'flock_devices.csv', 'text/csv');
        }

        function exportGeoJSON() {
            if (filteredResults.length === 0) {
                alert('No results to export');
                return;
            }

            const features = filteredResults
                .filter(r => r.lat !== 'N/A' && r.lon !== 'N/A')
                .map(r => ({
                    type: 'Feature',
                    geometry: {
                        type: 'Point',
                        coordinates: [parseFloat(r.lon), parseFloat(r.lat)]
                    },
                    properties: {
                        mac: r.mac,
                        ssid: r.ssid,
                        deviceType: r.deviceType,
                        rssi: r.rssi,
                        channel: r.channel,
                        firstSeen: r.firstSeen
                    }
                }));

            const geojson = {
                type: 'FeatureCollection',
                features: features
            };

            downloadFile(JSON.stringify(geojson, null, 2), 'flock_devices.geojson', 'application/json');
        }

        function exportKML() {
            if (filteredResults.length === 0) {
                alert('No results to export');
                return;
            }

            let kml = '<?xml version="1.0" encoding="UTF-8"?>\\n';
            kml += '<kml xmlns="http://www.opengis.net/kml/2.2">\\n';
            kml += '<Document>\\n';
            kml += '  <name>Flock Safety Devices</name>\\n';
            kml += '  <description>Detected Flock Safety surveillance devices</description>\\n';

            // Styles
            kml += '  <Style id="battery">\\n';
            kml += '    <IconStyle><color>ff32cd32</color><scale>1.2</scale></IconStyle>\\n';
            kml += '  </Style>\\n';
            kml += '  <Style id="camera">\\n';
            kml += '    <IconStyle><color>ffffa658</color><scale>1.2</scale></IconStyle>\\n';
            kml += '  </Style>\\n';

            for (let r of filteredResults) {
                if (r.lat !== 'N/A' && r.lon !== 'N/A' && r.lat && r.lon) {
                    const styleId = r.deviceType.includes('Battery') ? 'battery' : 'camera';
                    kml += '  <Placemark>\\n';
                    kml += '    <name>' + escapeXml(r.mac) + '</name>\\n';
                    kml += '    <description><![CDATA[';
                    kml += 'SSID: ' + escapeHtml(r.ssid) + '<br>';
                    kml += 'Type: ' + escapeHtml(r.deviceType) + '<br>';
                    kml += 'Signal: ' + escapeHtml(r.rssi) + ' dBm<br>';
                    kml += 'Channel: ' + escapeHtml(r.channel) + '<br>';
                    kml += 'First Seen: ' + escapeHtml(r.firstSeen);
                    kml += ']]></description>\\n';
                    kml += '    <styleUrl>#' + styleId + '</styleUrl>\\n';
                    kml += '    <Point><coordinates>' + r.lon + ',' + r.lat + ',0</coordinates></Point>\\n';
                    kml += '  </Placemark>\\n';
                }
            }

            kml += '</Document>\\n</kml>';
            downloadFile(kml, 'flock_devices.kml', 'application/vnd.google-earth.kml+xml');
        }

        function escapeXml(text) {
            return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        function exportMapSVG() {
            if (filteredResults.length === 0 || !map) {
                alert('No map data to export');
                return;
            }

            const bounds = map.getBounds();
            const minLat = bounds.getSouth();
            const maxLat = bounds.getNorth();
            const minLon = bounds.getWest();
            const maxLon = bounds.getEast();

            const width = 1400;
            const height = 900;
            const paddingLeft = 80;
            const paddingRight = 50;
            const paddingTop = 60;
            const paddingBottom = 50;

            function latToY(lat) {
                return paddingTop + ((maxLat - lat) / (maxLat - minLat)) * (height - paddingTop - paddingBottom);
            }
            function lonToX(lon) {
                return paddingLeft + ((lon - minLon) / (maxLon - minLon)) * (width - paddingLeft - paddingRight);
            }

            let svg = '<?xml version="1.0" encoding="UTF-8"?>\\n';
            svg += '<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="' + height + '" viewBox="0 0 ' + width + ' ' + height + '">\\n';
            svg += '  <rect width="100%" height="100%" fill="#0d1117"/>\\n';
            svg += '  <text x="' + (width/2) + '" y="35" text-anchor="middle" fill="#ff0000" font-size="28" font-weight="bold" font-family="monospace">RINGMAST4R FLOCK HUNTER</text>\\n';
            svg += '  <rect x="' + paddingLeft + '" y="' + paddingTop + '" width="' + (width - paddingLeft - paddingRight) + '" height="' + (height - paddingTop - paddingBottom) + '" fill="#161b22" stroke="#30363d"/>\\n';

            // Grid lines
            for (let i = 0; i <= 4; i++) {
                const x = paddingLeft + i * (width - paddingLeft - paddingRight) / 4;
                const y = paddingTop + i * (height - paddingTop - paddingBottom) / 4;
                svg += '  <line x1="' + x + '" y1="' + paddingTop + '" x2="' + x + '" y2="' + (height-paddingBottom) + '" stroke="#30363d" stroke-width="0.5"/>\\n';
                svg += '  <line x1="' + paddingLeft + '" y1="' + y + '" x2="' + (width-paddingRight) + '" y2="' + y + '" stroke="#30363d" stroke-width="0.5"/>\\n';

                // Add coordinate labels on grid lines
                const latVal = maxLat - i * (maxLat - minLat) / 4;
                const lonVal = minLon + i * (maxLon - minLon) / 4;
                svg += '  <text x="' + (paddingLeft - 10) + '" y="' + (y + 4) + '" text-anchor="end" fill="#8b949e" font-size="11" font-family="monospace">' + latVal.toFixed(4) + '</text>\\n';
                svg += '  <text x="' + x + '" y="' + (height - paddingBottom + 20) + '" text-anchor="middle" fill="#8b949e" font-size="11" font-family="monospace">' + lonVal.toFixed(4) + '</text>\\n';
            }

            // Plot devices
            let batteryCount = 0, cameraCount = 0, customCount = 0;
            for (let r of filteredResults) {
                if (r.lat !== 'N/A' && r.lon !== 'N/A' && r.lat && r.lon) {
                    const lat = parseFloat(r.lat);
                    const lon = parseFloat(r.lon);
                    if (!isNaN(lat) && !isNaN(lon)) {
                        const x = lonToX(lon);
                        const y = latToY(lat);
                        let color;
                        if (r.deviceType.includes('Battery')) { color = '#32cd32'; batteryCount++; }
                        else if (r.deviceType.includes('Camera')) { color = '#58a6ff'; cameraCount++; }
                        else { color = '#8b949e'; customCount++; }

                        svg += '  <circle cx="' + x.toFixed(2) + '" cy="' + y.toFixed(2) + '" r="8" fill="' + color + '" stroke="#fff" stroke-width="2" opacity="0.8"/>\\n';
                    }
                }
            }

            // Legend (bottom right, inside the map area)
            const legendX = width - paddingRight - 240;
            const legendY = height - paddingBottom - 90;
            svg += '  <rect x="' + legendX + '" y="' + legendY + '" width="230" height="' + (customCount > 0 ? 85 : 60) + '" fill="#161b22" stroke="#30363d" rx="5" opacity="0.9"/>\\n';
            svg += '  <circle cx="' + (legendX + 15) + '" cy="' + (legendY + 20) + '" r="8" fill="#32cd32"/>\\n';
            svg += '  <text x="' + (legendX + 35) + '" y="' + (legendY + 25) + '" fill="#c9d1d9" font-size="14" font-family="monospace">Extended Battery (' + batteryCount + ')</text>\\n';
            svg += '  <circle cx="' + (legendX + 15) + '" cy="' + (legendY + 45) + '" r="8" fill="#58a6ff"/>\\n';
            svg += '  <text x="' + (legendX + 35) + '" y="' + (legendY + 50) + '" fill="#c9d1d9" font-size="14" font-family="monospace">WiFi Camera (' + cameraCount + ')</text>\\n';
            if (customCount > 0) {
                svg += '  <circle cx="' + (legendX + 15) + '" cy="' + (legendY + 70) + '" r="8" fill="#8b949e"/>\\n';
                svg += '  <text x="' + (legendX + 35) + '" y="' + (legendY + 75) + '" fill="#c9d1d9" font-size="14" font-family="monospace">Custom (' + customCount + ')</text>\\n';
            }

            svg += '</svg>';
            downloadFile(svg, 'flock_map.svg', 'image/svg+xml');
        }

        function downloadFile(content, filename, mimeType) {
            const blob = new Blob([content], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            URL.revokeObjectURL(url);
        }

        // OUI Management Functions
        function saveOUIs() {
            localStorage.setItem('flock_ouis', JSON.stringify(FLOCK_OUIS));
            initWorkers(); // Recreate workers with updated OUIs
        }

        function renderOUITable() {
            const tbody = document.getElementById('ouiTableBody');
            tbody.innerHTML = '';
            // Sort by device type first (Battery before Camera), then by OUI
            const sorted = Object.entries(FLOCK_OUIS).sort((a, b) => {
                const aType = a[1].includes('Battery') ? 0 : 1;
                const bType = b[1].includes('Battery') ? 0 : 1;
                if (aType !== bType) return aType - bType;
                return a[0].localeCompare(b[0]);
            });

            for (let [oui, type] of sorted) {
                const tr = document.createElement('tr');
                const isBattery = type.includes('Battery');
                const isCamera = type.includes('Camera');
                let typeClass, typeName;
                if (isBattery) {
                    typeClass = 'type-battery';
                    typeName = 'Extended Battery';
                } else if (isCamera) {
                    typeClass = 'type-camera';
                    typeName = 'WiFi Camera';
                } else {
                    typeClass = 'type-custom';
                    typeName = type.includes('(') ? type.split('(')[0].trim() : type;
                }
                const manufacturer = type.includes('(') ? type.split('(')[1].replace(')', '') : 'Custom';

                tr.innerHTML =
                    '<td><code>' + escapeHtml(oui) + '</code></td>' +
                    '<td><span class="device-type ' + typeClass + '">' + typeName + '</span></td>' +
                    '<td>' + escapeHtml(manufacturer) + '</td>' +
                    '<td class="action-col ' + (editMode ? '' : 'hidden') + '"><button class="delete-btn" onclick="deleteOUI(\\'' + oui + '\\')">Delete</button></td>';
                tbody.appendChild(tr);
            }
            document.getElementById('ouiCount').textContent = '(' + Object.keys(FLOCK_OUIS).length + ' OUIs)';
        }

        function toggleEditMode() {
            editMode = !editMode;
            const form = document.getElementById('ouiEditForm');
            const btn = document.getElementById('editToggleBtn');
            const actionCols = document.querySelectorAll('.action-col');

            if (editMode) {
                form.classList.remove('hidden');
                btn.textContent = 'Done Editing';
                actionCols.forEach(col => col.classList.remove('hidden'));
            } else {
                form.classList.add('hidden');
                btn.textContent = 'Edit OUIs';
                actionCols.forEach(col => col.classList.add('hidden'));
            }
        }

        function toggleCustomType() {
            const typeSelect = document.getElementById('newOuiType');
            const customInput = document.getElementById('newOuiCustomType');
            if (typeSelect.value === 'custom') {
                customInput.style.display = 'inline-block';
            } else {
                customInput.style.display = 'none';
            }
        }

        function addCustomOUI() {
            let prefix = document.getElementById('newOuiPrefix').value.trim().toUpperCase();
            const type = document.getElementById('newOuiType').value;
            const manufacturer = document.getElementById('newOuiManufacturer').value.trim() || 'Custom';
            const customTypeName = document.getElementById('newOuiCustomType').value.trim();

            // Normalize to XX:XX:XX format
            prefix = prefix.replace(/[^A-F0-9]/g, '');
            if (prefix.length !== 6) {
                alert('OUI prefix must be 6 hex characters (e.g., 04:0D:84 or 040D84)');
                return;
            }
            prefix = prefix.substring(0,2) + ':' + prefix.substring(2,4) + ':' + prefix.substring(4,6);

            if (FLOCK_OUIS[prefix]) {
                alert('OUI ' + prefix + ' already exists');
                return;
            }

            let deviceType;
            if (type === 'battery') {
                deviceType = 'Extended Battery (' + manufacturer + ')';
            } else if (type === 'camera') {
                deviceType = 'WiFi Camera (' + manufacturer + ')';
            } else {
                if (!customTypeName) {
                    alert('Please enter a custom type name');
                    return;
                }
                deviceType = customTypeName + ' (' + manufacturer + ')';
            }

            FLOCK_OUIS[prefix] = deviceType;
            saveOUIs();
            renderOUITable();

            // Clear inputs
            document.getElementById('newOuiPrefix').value = '';
            document.getElementById('newOuiManufacturer').value = '';
            document.getElementById('newOuiCustomType').value = '';
            document.getElementById('newOuiType').value = 'battery';
            document.getElementById('newOuiCustomType').style.display = 'none';
        }

        function deleteOUI(oui) {
            if (confirm('Delete OUI ' + oui + '?')) {
                delete FLOCK_OUIS[oui];
                saveOUIs();
                renderOUITable();
            }
        }

        function resetToDefaults() {
            if (confirm('Reset OUI list to defaults? This will remove all custom entries.')) {
                FLOCK_OUIS = {...DEFAULT_FLOCK_OUIS};
                saveOUIs();
                renderOUITable();
            }
        }

        function resetDropZone() {
            allResults = [];
            filteredResults = [];
            totalNetworksCount = 0;
            document.getElementById('results').classList.add('hidden');
            document.getElementById('dropZone').innerHTML =
                '<h3>Drop Wardriving Files or Folders Here</h3>' +
                '<p style="color: #8b949e; margin: 10px 0;">CSV, KML, Kismet, NetStumbler, inSSIDer, WiFiFoFum, and more</p>';
            if (map) {
                map.remove();
                map = null;
                markersLayer = null;
            }
        }

        // Initialize OUI table on load
        renderOUITable();
    </script>
</body>
</html>
"""

class WiGLEAnalyzerHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode())
        elif self.path.startswith('/gifs/'):
            from urllib.parse import unquote
            gif_name = unquote(self.path[6:])
            gif_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gifs', gif_name)
            if os.path.exists(gif_path):
                self.send_response(200)
                self.send_header('Content-type', 'image/gif')
                self.end_headers()
                with open(gif_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404)
        else:
            super().do_GET()

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    with socketserver.TCPServer(("", PORT), WiGLEAnalyzerHandler) as httpd:
        print(f"\n{'='*60}")
        print(f"  RINGMAST4R FLOCK HUNTER")
        print(f"  Server running on http://localhost:{PORT}")
        print(f"{'='*60}")
        print(f"\nDetects {len(FLOCK_OUIS)} IEEE-verified Flock Safety OUI prefixes")
        print(f"Drop wardriving CSV exports to scan for surveillance devices\n")
        print("Press Ctrl+C to stop the server\n")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")

if __name__ == "__main__":
    main()
