# 3105 PRO V2.1 — GitHub source package

This archive has the original `tool/` directory flattened into the repository root.

## Upload
Upload the extracted **files and folders**, not the ZIP itself, to your private GitHub repository.
Do not commit secrets, private keys, passwords, uploads, or generated outputs.

## Vercel preview caveat
The Flask app creates `uploads/` and `outputs/` next to `app.py`. Vercel functions generally have a read-only deployment filesystem; temporary writes must use `/tmp`, with ephemeral storage and request size/time limits. Therefore this source is **not yet verified deployable on Vercel**. Adapt runtime paths and request limits and test before deploying.

## Local run
`pip install -r requirements.txt`
`python app.py`
