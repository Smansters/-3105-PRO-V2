CÔNG CỤ 3105 PRO V1.4 - BẢN FIX DUPLICATE + NO SILENT DELETE
=============================================================

CẤU HÌNH CHÍNH
- Flask/Python, port 2006.
- MAGIC: 3105PATCH\x00.
- Password mặc định: MANVIP.
- Author mặc định: MANZ-VIP.
- PUBG: schema/keyAAD 2/2.
- Liên Quân: schema/keyAAD 9/9.

6 TAB GIỮ NGUYÊN
- TẠO 3105
- GIẢI NÉN
- KIỂM TRA
- CẬP NHẬT
- ĐỔI BUNDLE ID
- CÔNG CỤ ZIP

CÁC FIX QUAN TRỌNG
1. Duplicate target
   - Cùng (bundleID, relativePath) + cùng SHA-256: dedupe.
   - Cùng target + SHA-256 khác: ERROR và dừng build/update.
   - /zip/diagnose phân biệt DEDUPE và ERROR.

2. Liên Quân không silent delete
   - Không còn cơ chế chỉ giữ Resources/ rồi bỏ file ngoài Resources/.
   - File hệ thống đáng chú ý chỉ WARN, không tự xóa.

3. ZIP export artifacts
   - Chỉ bỏ các file được nhận diện rõ là báo cáo/phụ trợ do 3105 Pro tạo
     (ví dụ conflicts/, _xung_dot/, conflict_report.json, manifest do tool tạo).
   - Các file bị bỏ đều xuất hiện trong diagnostics/warning; không còn bỏ âm thầm.
   - payload/ không còn bị bỏ chỉ vì ZIP có file ngoài payload/.

4. PUBG
   - Không nhập tên PAK mới => giữ nguyên tên gốc.

5. Verify
   - Build/update/rebundle phải verify trước khi trả file tải xuống.

KIỂM THỬ BẢN FIX
- py_compile: PASS cho app.py và 3105tool.py.
- Engine regression tests: 5/5 PASS cho no-silent-delete, duplicate cùng SHA,
  duplicate khác SHA, payload collision và export-artifact diagnostics.
- Chưa chạy Flask integration test trong môi trường đóng gói này vì runtime hiện
  không cài module Flask; requirements.txt vẫn khai báo flask + cryptography.

CHẠY TRỰC TIẾP
  pip install -r requirements.txt
  python app.py

CHẠY DOCKER
  docker compose up -d --build
