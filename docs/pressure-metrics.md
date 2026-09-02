# Pressure and accuracy metrics

_Not yet generated._

This file is regenerated automatically by `.github/workflows/pressure-test.yml` on every
scheduled (daily, 03:00 UTC) or manually-dispatched run of the pressure suite
(`mvn verify -Ppressure`), and committed back to `main` with real numbers.

Until the first such run completes after this change merges, this is a placeholder.
To generate it locally instead of waiting on CI:

```bash
mvn verify -Ppressure
python3 scripts/generate_pressure_report.py
```

See `EndpointPressureIT.java` and `ScanAccuracyIT.java` under
`src/test/java/com/antivirus/pressure/` for what each metric measures, and
`scripts/generate_pressure_report.py` for how this file and `pressure-metrics.svg`
are rendered from the raw JSON in `target/pressure-metrics/`.
