FROM python:3.10-slim

WORKDIR /app

# Khắc phục lỗi encoding nếu có
ENV PYTHONIOENCODING=utf-8

# Cài đặt thư viện
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ code vào container
COPY . .

# Tạo sẵn thư mục để tránh lỗi phân quyền
RUN mkdir -p uploads outputs

# Mở port 2006
EXPOSE 2006

CMD ["python", "app.py"]