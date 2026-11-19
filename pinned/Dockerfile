# Ghim thư viện của image lab đúng như máy gốc. Phiên bản đọc từ models/full1/model.joblib (khóa "versions"):
#   Python 3.11.17, scikit-learn 1.9.1, numpy 1.26.4, pandas 2.3.3.
# Mô hình được lưu bằng scikit-learn 1.9.1; nạp bằng bản khác có thể báo lỗi hoặc cho điểm khác. requirements.txt chỉ ghi
# khoảng phiên bản và nằm trong bản kê khóa nên không sửa. Tệp này dựng lại image siem-ai-lab:local từ chính image do
# setup/02_up.sh build, chỉ thay ba gói. Bản vá của Python có thể khác 3.11.17 (do image python:3.11-slim), không ảnh hưởng.
#
# Dùng sau setup/02_up.sh, trước khi bật ai-service (và chạy lại mỗi khi build lại image lab):
#   docker build -t siem-ai-lab:local -f pinned/Dockerfile pinned
FROM siem-ai-lab:local
RUN pip install --no-cache-dir "scikit-learn==1.9.1" "numpy==1.26.4" "pandas==2.3.3" \
 && python3 -c "import sys, sklearn, numpy, pandas; print('python', sys.version.split()[0], '| scikit-learn', sklearn.__version__, '| numpy', numpy.__version__, '| pandas', pandas.__version__)"
