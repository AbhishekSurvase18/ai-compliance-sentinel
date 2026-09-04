# Operator runbook

## Start dashboard

```powershell
python -m streamlit run app.py --server.port 8501
```

## Run validation

```powershell
python app.py
python -m unittest discover -s tests -v
```

## Start API

```powershell
$env:SENTINEL_API_KEY="use-a-managed-secret"
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

## Check health

`GET /health` is public and reports audit-chain and storage health. Analysis endpoints require `Authorization: Bearer <SENTINEL_API_KEY>`.

## Incident handling

If the audit chain is degraded, stop report finalization, preserve the storage volume, and page the compliance platform owner. If an agent fails or evidence is missing, retain the case in review status. Never release a sanctions hold or close a critical alert automatically.

## Reset development artifacts

Delete only local development files under `reports/` after confirming no legal hold exists. Do not use this procedure for production retention-locked storage.
