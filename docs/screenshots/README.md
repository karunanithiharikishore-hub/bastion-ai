# Screenshots

Bastion AI dashboard, captured from the bundled **synthetic** sample data
(`samples/`) in rules-only mode. Never capture real logs.

| filename | view |
|---|---|
| `01-intake.png` | Hero + "Drop your logs here" intake zone |
| `02-verdict.png` | Analyst verdict banner |
| `03-summary.png` | Attack summary (how they got in / what they did) |
| `04-storyline.png` | Kill-chain storyline |
| `05-swarm.png` | Agent swarm constellation + specialist findings |

## Regenerate

```bash
bastion serve samples --llm off --port 8787 &
python3 scripts/capture_screenshots.py docs/screenshots
```

Needs Playwright (`pip install playwright`) and Google Chrome.
