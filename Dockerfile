FROM python:3.11-slim

# 安装 shred 工具 (coreutils)
RUN apt-get update && apt-get install -y coreutils findutils && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 暴露端口
EXPOSE 46746

# 环境变量默认值
ENV AEGIS_DATA_DIR=/app/data
ENV TEMPLATE_DIR=/app/templates
ENV PORT=46746

CMD ["python", "main.py"]
