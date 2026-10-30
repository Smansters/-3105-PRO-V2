# Test report — 3105 PRO V1.4 Hardened

- Python compile `app.py`, `3105tool.py`: PASS.
- `python -m unittest discover -s tests -v`: PASS (7/7).
- ZIP traversal / absolute / Windows drive: PASS.
- Duplicate ZIP entry: PASS.
- Nested ZIP bundle context: PASS.
- Nested ZIP depth limit: PASS.
- Uncompressed size limit: PASS.
- Preview/Build target comparison on LQ sample: PASS.
- Build -> decrypt -> verify on 5-server PUBG synthetic fixture: PASS (schema 9, 5 rules).
- Flask HTTP integration: BLOCKED (Flask unavailable in current runtime; pip install failed due network DNS).
- Compatibility with real iOS app 3105: NOT TESTED.
- Full Update/Rebundle regression: NOT TESTED.
- Actual large user ZIP performance: NOT TESTED.

Rủi ro: giới hạn nén có thể từ chối ZIP hợp lệ nhưng nén rất mạnh; toàn bộ luồng Flask chưa được kiểm chứng. Không tuyên bố toàn bộ sản phẩm đã đạt kiểm thử tích hợp.
