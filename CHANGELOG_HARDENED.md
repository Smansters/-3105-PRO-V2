# 3105 PRO V1.4 — Changelog Hardened

Nguồn nền: 3105_PRO_V1.4_PUBG_5_SERVER_UPGRADE.zip (source đã gửi trong cuộc trò chuyện). Không thay thế kiến trúc hiện tại.

## Thay đổi
- 3105tool.py: kiểm tra tên ZIP tuyệt đối, ổ đĩa Windows, path traversal, tên trùng.
- 3105tool.py: giới hạn ZIP 10.000 mục, 512 MiB dữ liệu giải nén và tỷ lệ nén bất thường >200:1 (với mục >1 MiB).
- 3105tool.py: giới hạn nested ZIP 2 tầng; ZIP con lỗi không bị biến thành rule; giữ ngữ cảnh Bundle ID khi ZIP con nằm dưới thư mục Bundle ID.
- tests/test_hardening.py: 7 kiểm thử tự động, bao gồm build/verify 5 server.
- Không thay đổi Flask UI, schema, AES-GCM, PBKDF2, AAD hoặc các preset.

## Lưu ý tương thích
Các ZIP từng được chấp nhận dù chứa mục nguy hiểm, ZIP con lỗi hoặc ZIP quá giới hạn sẽ bị từ chối. Đây là thay đổi có chủ đích để tránh tạo rule không an toàn. Các ngưỡng bảo vệ là giá trị mặc định trong code, có thể cần điều chỉnh sau kiểm thử với ZIP dung lượng lớn thực tế.
