# Biên bản sửa và kiểm tra — IAM302t Group 6

Ngày kiểm tra: **2026-10-28**. Phạm vi: sửa nguồn báo cáo E5, tính công bằng E4 và số cột bảng thống kê. Đã đọc lại PDF giảng viên (9 trang), `readme.md`, `RUNNING.md` và code liên quan trong `byteplot/`.

Các thay đổi không sửa RQ1–RQ4, H1–H4, kiến trúc CNN/probe, công thức metric, CLI hoặc file kết quả lịch sử. Kiểm tra này xác nhận phần mềm trên dữ liệu synthetic; chưa xác nhận hiệu quả phát hiện malware thật.

## File thay đổi và lý do

| File | Thay đổi |
| --- | --- |
| [byteplot/report.py](byteplot/report.py) | Tách bảng E2/E5/B1; thêm `experiment` cho CSV trung tâm; lấy E5 từ đúng run E5, không fallback E2; sửa header thống kê thành 8 cột |
| [byteplot/engine.py](byteplot/engine.py) | Chỉ áp dụng `benign_packed_keep` cho train; validation luôn giữ toàn bộ mẫu thuộc thiết kế validation, cùng quy tắc cân bằng parent đã có |
| [byteplot/experiments.py](byteplot/experiments.py) | Thêm metadata E4 vào `suite.json`: validation giữ benign packed 100%, test cố định; không thay recipe E1/E2/E3/E5 |
| [tests/test_regressions.py](tests/test_regressions.py) | Thêm 5 trường hợp regression: nguồn E5 trong suite đầy đủ/chỉ E5/không E5; định dạng và mean/SD; E4 cố định holdout trên hai seed |
| [RUNNING.md](RUNNING.md) | Mô tả schema CSV mới, các bảng riêng, E4 chỉ đổi train, cách chạy lại và liên kết tới output sau sửa |
| [REVIEW.md](REVIEW.md) | Biên bản bàn giao, kết quả kiểm thử thực tế và phần còn cần dữ liệu/công cụ thật |

Đã kiểm tra `byteplot/io.py`: hàm chọn mẫu và quy tắc chống rò rỉ theo `parent_sha256` giữ nguyên. Các file code khác, gồm `metrics.py`, `models.py`, `representation.py`, `vm_tools.py` và `cli.py`, không thay đổi. Các file trong `graphify-out/` được cập nhật tự động theo quy tắc `AGENTS.md` của môi trường; chúng không tham gia train hoặc tính metric.

## Thay đổi hành vi

**E5:** `central_table.csv` có cột `experiment` và các dòng riêng cho E2, E5 và B1 (E1). E5 ghi `train_variants=V1`, chỉ điền F1 V2 từ run E5; V0/V1 để trống. V2 của E2 vẫn được giữ dưới nhãn E2 và ghi là diagnostic trong Markdown. Nếu chưa chạy E5, báo thiếu kết quả; không dùng số của E2 để thay.

**B1:** tiếp tục dùng C1 của E1 train V0 và đánh giá V1u. Cột V1 của B1 là điểm sau unpack, V2 là N/A. Báo cáo nêu rõ khác biệt chế độ train/đánh giá với E2/E5 và vẫn dẫn tới đánh giá trên các parent đủ cặp V0/V1/V1u.

**E4:** hai điều kiện dùng cùng validation cân bằng và cùng test với mỗi seed. Chỉ điều kiện rare loại bớt benign V1 trong train. Không đổi phép chia parent, ngưỡng dự đoán, optimizer, class-weight policy hoặc cách chọn checkpoint. Kết quả E4 mới có thể khác vì checkpoint được chọn trên validation đúng; không chỉnh sửa thủ công các điểm số đã lưu.

**Markdown:** bảng Mean and seed variation có đúng Experiment, Channel, Condition, Fraction, Variant, Seeds, Mean F1, Sample SD. Mean và sample SD (`ddof=1`) vẫn được tính như trước; một seed vẫn ghi SD là N/A.

## Kiểm thử đã thực sự chạy

| Kiểm tra | Trạng thái | Bằng chứng |
| --- | --- | --- |
| Pytest có sẵn trước sửa | **PASS** | 13 passed |
| Regression trên code trước sửa | **FAIL đúng kỳ vọng** | Cả 5 trường hợp mới phát hiện lỗi, gồm validation E4 bị đổi và bảng trung tâm không có nguồn E5 riêng |
| Regression sau sửa | **PASS** | 5 passed |
| Toàn bộ pytest sau sửa | **PASS** | Lần cuối: 18 passed in 13.38s |
| `python -m compileall -q byteplot tests` | **PASS** | Lệnh hoàn thành thành công, không có lỗi cú pháp |
| Parse toàn bộ file Python dự án, gồm script dữ liệu đi kèm | **PASS** | 16 file được `ast.parse`; không thực thi script xử lý binary |
| Demo CLI đầy đủ | **PASS** | 160 mẫu synthetic, 0 lỗi prepare; E0–E5 không có mục bị skip |
| C1–C4, B1 và probe | **PASS trên synthetic** | 17 run classifier, 1 entropy probe; có audit E0 và đánh giá B1 trên cặp khớp |
| CSV và Markdown | **PASS** | 68 dòng results, 9 dòng central; mọi bảng khớp số cột, bảng mean có 8 cột |
| Tương thích E1/E2/E3/E5 | **PASS trên demo đối chiếu** | 52 giá trị Macro-F1 ngoài E4 khớp output demo trước sửa |
| Bảo toàn output lịch sử | **PASS** | Hash các file đã snapshot trong `demo-output/runs/` không thay đổi |
| PE thật, DiE/UPX thực tế, MPRESS/ASPack | **Chưa chạy** | Không dùng binary malware thật trong phiên kiểm tra; test wrapper chỉ mô phỏng công cụ |
| GPU/Colab, 3 seed trên tập nghiên cứu thật | **Chưa chạy** | Demo dùng CPU, 1 epoch, seed 17; regression E4 và test E5 dùng thêm seed 37 |

Lệnh đã chạy:

```powershell
.\.venv\Scripts\python.exe -m compileall -q byteplot tests
.\.venv\Scripts\python.exe -m pytest tests/test_regressions.py -q --tb=short
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m byteplot demo --out runs/review-demo --epochs 1
```

Không có test sản phẩm nào còn FAIL ở lần chạy cuối. Các regression FAIL trước sửa là bằng chứng tái hiện lỗi, không phải kết quả kiểm tra sau sửa.

## Đối chiếu E4 từ output demo mới

| Kênh | Train balanced | Train rare | Validation mỗi điều kiện | Test mỗi điều kiện |
| --- | --- | --- | --- | --- |
| C1 | 56 | 44 | 12 | 24 |
| C2 | 56 | 44 | 12 | 24 |

Đã so sánh byte của `selected_val.csv`: balanced và rare giống hệt nhau. Các dòng bị loại khỏi train đều có label 0, variant V1. Danh tính mẫu test giống nhau giữa hai điều kiện; tập parent train/validation/test không giao nhau. Regression cũng kiểm tra các điều kiện này trên seed 17 và 37.

## Output bàn giao

- [REPORT.md sau sửa](runs/review-demo/runs/REPORT.md).
- [central_table.csv](runs/review-demo/runs/central_table.csv): tách rõ nguồn E2/E5/E1.
- [results.csv](runs/review-demo/runs/results.csv): số liệu từng run/variant do code thực sự xuất.
- [verification.json](runs/review-demo/verification.json): kết quả đối chiếu file, nguồn số liệu, holdout E4 và số cột bảng.
- [comparisons.json](runs/review-demo/runs/comparisons.json): chênh F1, McNemar và gap learning curve.

Các output mới nằm ở `runs/review-demo/`. Thư mục `demo-output/` và archive `byteplot.zip` có sẵn được giữ nguyên. Để tạo bản chạy khác, đổi tên `--out`; không ghi đè output cũ. E4 đã chạy bằng bản code cũ cần chạy lại để có lựa chọn checkpoint trên validation cố định.

## Phần vẫn cần dữ liệu và công cụ thật

1. Thu binary benign/malware đúng nguồn; vector `bodmas.npz` hiện có không thay được binary để dựng byteplot và tạo cặp.
2. Trong VM, dùng DiE kiểm tra mẫu gốc, loại pack/protect đã có và xác nhận biến thể sau pack/unpack; kiểm tra JSON tương thích phiên bản công cụ thực tế.
3. Dùng UPX tạo V1, unpack V1u cho B1 và ghi tỉ lệ thất bại theo nhóm.
4. Dùng MPRESS/ASPack tạo V2 từ cùng mẫu gốc và nhập manifest đúng parent để chạy E5 thật.
5. Kiểm tra artifact nguồn, đủ quy mô theo đề, rồi chạy E0–E5 với 3 seed và các mức learning curve trên tập thật.

Synthetic trong demo và các điểm số giả định của unit test chỉ phục vụ kiểm tra code. Không dùng chúng để kết luận H1–H4, tính dư thừa của entropy hoặc hiệu quả phát hiện malware.
