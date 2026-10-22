#!/usr/bin/env python3
"""Embeds docs/live/*.json (results of the live Esmeralda run) into docs/index.html."""
import json, pathlib
here = pathlib.Path(__file__).parent
live = json.loads((here / "live" / "deployment.json").read_text())
verify = json.loads((here / "live" / "verify.json").read_text())
html = (here / "index.template.html").read_text().replace("/*LIVE*/null", json.dumps(live)).replace("/*VERIFY*/null", json.dumps(verify))
(here / "index.html").write_text(html)
print("wrote", here / "index.html")
