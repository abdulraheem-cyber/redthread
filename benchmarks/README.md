# Benchmarks

Each JSON file in this directory describes the issues a target is known to contain. `redthread eval` matches validated findings from a run against those expectations.

`truth-labshop.json` covers the bundled `labs/labshop.py` application. The seven expectations produce eight findings because both cross-account order reads are reported separately while object-level authorisation is one expected class.

Run the lab, execute a scan, and score it:

```console
python -m labs.labshop --port 8000
redthread run -c examples/redthread.toml
redthread eval --run runs/<timestamp>-labshop --truth benchmarks/truth-labshop.json --strict
```

The recorded result and the metric definitions are in `../docs/benchmarks.md`. The suite is a regression check, not an independent evaluation of detection quality.
