# Merge từ tool.zip đang chạy

- Giữ nguyên cấu trúc thư mục và các file triển khai của tool.zip.
- Áp dụng bổ sung PUBG KR/TW/BGMI, preset 5 server, endpoint tách 5 server từ bản HARDENED.
- Áp dụng giới hạn ZIP và bộ test bảo vệ đường dẫn từ HARDENED.
- Sửa lỗi JavaScript: handler tách 5 server trước đây nằm trong thẻ script CDN Tailwind nên không chạy; chuyển vào script riêng sau khi DOM sẵn sàng.
- Flask HTTP chưa được xác minh nếu thiếu Flask trong runtime.
