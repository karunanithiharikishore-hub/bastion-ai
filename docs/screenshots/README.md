# Screenshots

Drop PNGs here with these exact names so the README/GITHUB embeds resolve:

| filename | what to capture |
|---|---|
| `01-intake.png` | The top "① Drop your logs here" intake zone + hero metrics |
| `02-verdict.png` | The Analyst Verdict banner (real / benign / needs-review) |
| `03-summary.png` | The Attack Summary (how they got in / what they did) |
| `04-storyline.png` | The 3D kill-chain storyline |
| `05-swarm.png` | The Agent Swarm constellation + specialist findings |

## How to capture (macOS)

1. Start the dashboard:
   ```bash
   cd .. && bastion serve samples --window 120 --open
   ```
2. In the browser, use **Cmd+Shift+4** then **Space** to capture the window, or
   **Cmd+Shift+4** to select a region.
3. Save each shot into this folder with the names above.

Use only the bundled **synthetic** sample data for screenshots — never real logs.
