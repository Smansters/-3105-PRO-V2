# 3105 PRO V1.4 Hardened

Dựa trên source 5-server V1.4 trước đó; giữ nguyên sáu tab và Flask port 2006.

## Cài đặt

```bash
python -m pip install -r requirements.txt
python app.py
```

Mở `http://localhost:2006` (chỉ môi trường local/dev). Không đưa Flask development server trực tiếp lên Internet.

## Chạy test

```bash
python -m unittest discover -s tests -v
python -m py_compile app.py 3105tool.py
```

## Lưu ý

File .3105 được mã hóa theo cấu trúc hiện có; không đổi schema hay AAD. Khi chạy public, cần reverse proxy, xác thực, HTTPS, giới hạn request và kiểm tra bảo mật bổ sung. Đọc `TEST_REPORT.md` và `CHANGELOG_HARDENED.md` trước khi triển khai.
