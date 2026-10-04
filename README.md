# Nmap Scan Detection & Packet Analysis Using Wireshark

This project analyzes pre-recorded Nmap scan packet captures (from Wireshark's official sample captures) to identify how different Nmap scanning techniques appear at the packet level, and what a defender could realistically determine from that traffic alone.

Unlike my first project (running live Nmap scans), this one works from the defender's side: given a recorded capture, what can you tell about the scan, and what can't you tell because the evidence is incomplete?

## Why this dataset

The captures come from Wireshark's official public sample captures page (wiki.wireshark.org/SampleCaptures), specifically `NMap-Captures.zip`, which contains recordings of several different Nmap scan techniques. This is not traffic from a live attack against a real system — it's a standard practice/training dataset.

## What's in this repo

```
nmap-wireshark-analysis/
├── README.md
├── report/
│   └── NMap-Wireshark-Analysis-Report.md
├── screenshots/
│   └── (packet-level evidence for each scan type)
└── evidence/
    └── findings.txt
```

## Scans analyzed

1. **Standard scan** — 2,000 outbound SYN probes, no responses captured
2. **ACK scan** — 2 ACK probes to port 80, no response captured
3. **OS scan** — mix of SYN probes and specially-crafted non-SYN probes (OS fingerprinting pattern), no responses captured
4. **Successful OS scan** — same pattern, but this capture includes real target responses (SYN-ACK, RST-ACK, RST)
5. **Zombie/idle scan** — three-host traffic pattern; investigated IP ID sequencing but did not confirm which host was the "zombie"

Full write-up, evidence, and reasoning for each is in [report/NMap-Wireshark-Analysis-Report.pdf](report/NMap-Wireshark-Analysis-Report.pdf) (also available as [Markdown](report/NMap-Wireshark-Analysis-Report.md)).

**Skills practiced:** packet-level traffic analysis, Wireshark display filters and statistics tools (Conversations, Protocol Hierarchy), distinguishing confirmed evidence from unsupported conclusions, comparing scan techniques by their network footprint.

## A note on method

Several of these captures only contain traffic in one direction, meaning I couldn't determine actual port states for some of the scans. I chose to report that limitation directly rather than guess — I think that's a more honest and more useful skill to show than pretending the evidence says more than it does.
