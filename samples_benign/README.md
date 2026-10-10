# Benign sample: approved maintenance window (SYNTHETIC)

A **false-positive test case**. Everything here is legitimate IT work, but it is
deliberately shaped to trip Bastion AI's rule-based detections, so you can check
whether the analysis tells it apart from a real attack.

Kept outside `samples/` on purpose: ingestion walks subfolders, so putting this
there would mix it into the attack-chain sample.

## What actually happened

Change **CHG0042117**, opened and closed in the logs, 22:00-22:45 UTC:

| Activity | Looks like | Why it is benign |
|---|---|---|
| `jsmith` fails an SSH password twice, then logs in with a public key from jump host `10.0.5.20` | T1110 brute force | Internal jump host, two typos, key-based success |
| `sudo apt-get install --only-upgrade openssl` | privilege escalation | The approved patch |
| `systemctl enable node_exporter` | T1543 new service | Approved monitoring rollout |
| `crontab -e` for nightly logrotate | T1053 scheduled task | Approved fix |
| RDP from the jump host to `win-app02` (MFA satisfied) | T1021 lateral movement | Normal admin path |
| `powershell Get-HotFix`, `certutil -hashfile` on the installer | T1059 / T1105 tool download | Inventory and checksum verification, nothing downloaded by certutil |
| Signed Windows update installed, planned restart | | The approved patch |
| rsync "upload" to internal `backup01` | T1048 exfiltration | Nightly backup to an internal host |

DNS and firewall traffic goes only to update mirrors and internal hosts.

## Expected behaviour

- `--llm off` (rules only): scores it **90/100 critical, "likely real attack"**,
  and the rule-based Tier-2 confirms it. That is the false positive this sample
  exists to show.
- With a model backbone, the Tier-2 agent should find the change-ticket trail
  and dismiss the incident.

```bash
bastion analyze samples_benign --llm off
bastion analyze samples_benign --llm auto
```

All data is fabricated. Public IPs use the RFC 5737 documentation range
`192.0.2.0/24`; internal IPs are RFC 1918. Domain names are real vendor update
endpoints, used only as realistic benign destinations.
