# Hướng dẫn chạy code Group 6

## 1. Chạy thử ngay trên máy hiện tại

Mở PowerShell ở thư mục `C:\Users\TRUNG KIEN\ProjectV1`. Môi trường `.venv` đã được cài trong phiên triển khai này. Chạy:

```powershell
.\.venv\Scripts\python.exe -m byteplot demo --out demo-my-run --epochs 1
```

Không cần activate môi trường. Lệnh này tự tạo dữ liệu byte giả lập, tạo ảnh 64×64, chia tập theo mẫu gốc, chạy E0–E5 với một seed và hai mức learning curve 50%/100%. Không cần GPU, binary malware, UPX hoặc DiE. Lần đầu import thư viện có thể mất thêm thời gian.

**Kết quả demo chỉ kiểm tra phần mềm.** V1 dùng zlib, V2 dùng XOR và nhãn vùng PE được giả lập; chúng không phải UPX/MPRESS hoặc PE thật. Một epoch và một seed không đủ cho kết luận nghiên cứu. F1 thấp ở demo không có nghĩa pipeline bị lỗi.

Bản demo kiểm tra sau sửa nằm tại `runs/review-demo/`: mở [báo cáo demo mới](runs/review-demo/runs/REPORT.md) và [biểu đồ learning curve](runs/review-demo/runs/learning_curve.png). Bộ `demo-output/` cũ vẫn được giữ làm lịch sử và nguồn feature cho các ví dụ train riêng bên dưới. Để chạy lại, dùng tên output mới, ví dụ `--out demo-my-run-2`; chương trình từ chối ghi đè checkpoint/dataset đã có.

Sau lệnh trên, xem:

| File / thư mục | Nội dung |
| --- | --- |
| `demo-my-run/prepared/prepared.csv` | Manifest ảnh, nhãn, hash, biến thể và split |
| `demo-my-run/prepared/dataset.json` | Cấu hình biểu diễn, số lỗi và tỉ lệ cắt ảnh |
| `demo-my-run/prepared/prepare_errors.csv` | Các mẫu không tạo ảnh được |
| `demo-my-run/runs/REPORT.md` | Báo cáo tổng hợp và trung bình theo seed |
| `demo-my-run/runs/central_table.csv` | Bảng có cột `experiment`: E2 train V0+V1, E5 train V1/test V2, B1 từ E1 train V0 |
| `demo-my-run/runs/results.csv` | Kết quả từng cấu hình, seed, mức dữ liệu và biến thể |
| `demo-my-run/runs/learning_curve.png` | F1 C1/C2 trên V1 theo lượng dữ liệu |
| `demo-my-run/runs/examples/` | Hình grayscale, entropy, vùng PE và mask |
| `demo-my-run/runs/comparisons.json` | Chênh F1, McNemar và độ thu hẹp khoảng cách learning curve |
| `demo-my-run/runs/E3/probe_seed_17/metrics.json` | MSE và tương quan entropy dự đoán |
| Mỗi thư mục model | `checkpoint.pt`, `history.csv`, `predictions.csv`, `metrics.json`, cấu hình và danh sách train/validation |

Có thể dùng script tương đương:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run-demo.ps1 -OutputDir demo-script-run -Epochs 1
```

## 2. Cài lại môi trường trên máy khác

Code hỗ trợ Python **3.10 trở lên**; môi trường đã kiểm tra dùng Python 3.12 và PyTorch CPU. `requirements-tested.txt` lưu phiên bản thư viện thực tế đã dùng. File này dành cho tái lập môi trường đã kiểm tra; trên nền tảng khác có thể dùng các khoảng phiên bản trong `requirements.txt`.

Nếu máy đã cài `uv`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup.ps1
```

Script tạo `.venv`, cài PyTorch CPU từ kho chính thức và các thư viện còn lại. Nếu không có `uv`, dùng Python có sẵn:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install "torch>=2.4,<3" --index-url https://download.pytorch.org/whl/cpu
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Nếu Windows mở Microsoft Store khi gõ `python`, dùng đường dẫn `.\.venv\Scripts\python.exe` như các ví dụ. Không cần đổi execution policy toàn hệ thống.

Trên Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install 'torch>=2.4,<3' --index-url https://download.pytorch.org/whl/cpu
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m byteplot demo --out demo-my-run
```

## 3. Train riêng từng model trên dữ liệu demo

Các lệnh dưới đây dùng bộ demo đã tạo sẵn trong `demo-output/`. `--manifest` của lệnh train/probe/suite phải trỏ đến **`prepared.csv`**, không phải manifest binary gốc.

```powershell
# CNN grayscale + entropy, train trên V0/V1, đánh giá tất cả biến thể test có sẵn
.\.venv\Scripts\python.exe -m byteplot train --manifest demo-output/prepared/prepared.csv --out runs/my-c2 --channel C2 --variants V0 V1 --epochs 3 --seed 17 --device cpu

# Probe: grayscale -> entropy, loss bỏ vùng padding
.\.venv\Scripts\python.exe -m byteplot probe --manifest demo-output/prepared/prepared.csv --out runs/my-probe --variants V0 V1 --epochs 3 --seed 17

# Nạp checkpoint classifier và dự đoán lại split test
.\.venv\Scripts\python.exe -m byteplot predict --checkpoint runs/my-c2/checkpoint.pt --manifest demo-output/prepared/prepared.csv --out runs/my-c2/reloaded-predictions.csv

# Xuất ảnh minh họa
.\.venv\Scripts\python.exe -m byteplot visualize --manifest demo-output/prepared/prepared.csv --out runs/channel-images --limit 8
```

`C1 = grayscale`, `C2 = grayscale + entropy`, `C3 = grayscale + vùng PE`, `C4 = cả ba`. Mask được dùng cho pooling ở cuối CNN và loss probe, không thêm thành kênh đầu vào. Convolution vẫn thấy biên padding; cần xem padding là biến kiểm soát trong báo cáo.

## 4. Chuẩn bị dữ liệu PE thật trong VM

Phần này thực hiện trong **VM cô lập theo yêu cầu của đề**. Code không khởi chạy mẫu PE. Các process bên ngoài duy nhất của lệnh `index`/`variants` là công cụ DiE và UPX do bạn chỉ định. Trên máy hiện tại chưa có dữ liệu binary nghiên cứu đầy đủ; các wrapper UPX/DiE đã có kiểm thử mô phỏng, chưa được xác nhận với bản công cụ cài trong VM của bạn.

### 4.1. Cần có gì

- Binary malware được phép sử dụng từ BODMAS/MalwareBazaar và binary benign tự thu. Bộ `bodmas.npz` hiện có chứa vector đặc trưng, không phải ảnh byteplot và không thay thế binary.
- DiE CLI (`diec`/`diec.exe`) hỗ trợ xuất JSON với `-j`.
- UPX CLI (`upx`/`upx.exe`).
- Với E5: V2 được tạo bằng MPRESS/ASPack trong VM Windows. Code hiện nhập V2 đã tạo sẵn; không tự cài hoặc tự gọi hai packer này.
- Nếu BODMAS còn ở trạng thái disarmed, việc chuẩn bị dữ liệu gốc theo quy trình của bộ dữ liệu phải làm riêng trong VM; pipeline không tự khôi phục malware.

Ví dụ bố trí trong VM:

```text
data/
  raw/
    benign/      # PE hợp lệ
    malware/     # PE malware dùng trong nghiên cứu
  v2/            # <parent_sha256>.bin đã pack bằng packer thứ hai, nếu có
```

### 4.2. Index, DiE và lọc mẫu đã pack sẵn

Chạy từ thư mục dự án trong VM; đổi đường dẫn công cụ theo nơi bạn cài:

```powershell
.\.venv\Scripts\python.exe -m byteplot index --benign data/raw/benign --malware data/raw/malware --out data/index --die C:/Tools/DiE/diec.exe --metadata drive-download-20261015T055410Z-1-001/bodmas_metadata.csv
```

Kết quả `data/index/originals.csv` chứa cả mẫu hợp lệ và mẫu bị loại, với `die_status` cùng `status`. Chỉ mẫu `die_status=clean` mới được lấy làm V0. `clean` có nghĩa không phát hiện packing trong những detection DiE mà parser nhận diện, không chứng minh file chưa từng bị pack. JSON không nhận diện được/lỗi công cụ sẽ thành `unknown`, không tự coi là sạch. Xem log trong `data/index/die/` và đối chiếu JSON của phiên bản DiE bạn sử dụng.

Tham số metadata là tùy chọn; hỗ trợ cột `sha` hoặc `sha256`, và cột `family`. Nhãn benign/malware lấy theo thư mục đầu vào, không suy từ tên file. Các bản trùng hash được gộp; xung đột nhãn bị từ chối.

### 4.3. Tạo V1, V1u và nhập V2

```powershell
.\.venv\Scripts\python.exe -m byteplot variants --manifest data/index/originals.csv --out data/variants --upx C:/Tools/UPX/upx.exe --die C:/Tools/DiE/diec.exe
```

Lệnh tạo V1 bằng UPX, sau đó V1u bằng UPX `-d`, luôn dùng file output riêng. DiE kiểm tra lại V1/V1u; mẫu thất bại hoặc không xác minh được vẫn được ghi trong `data/variants/manifest.csv`. Xem `tool_log`, `error`, `die_status` và `status` trước khi train.

Nếu có V2, đặt tên từng file **`<parent_sha256>.bin`** và chạy vào thư mục output mới:

```powershell
.\.venv\Scripts\python.exe -m byteplot variants --manifest data/index/originals.csv --out data/variants-with-v2 --upx C:/Tools/UPX/upx.exe --die C:/Tools/DiE/diec.exe --v2-dir data/v2 --v2-packer MPRESS
```

Giữ nhật ký ánh xạ V2 về bản gốc; tên file là quy ước nhập, không tự chứng minh quan hệ gốc. Không dùng UPX thay cho packer thứ hai rồi gọi đó là E5.

Nếu bạn đã có pipeline dữ liệu khác, có thể tự tạo CSV theo [mẫu manifest](examples/manifest.template.csv). Các trường chính:

| Trường | Quy ước |
| --- | --- |
| `path` | Đường dẫn tuyệt đối hoặc tương đối so với CSV binary |
| `label` | `0`: benign; `1`: malware |
| `parent_sha256` | SHA-256 chữ thường của V0; giữ nguyên cho V1/V1u/V2 |
| `sha256` | SHA-256 của chính biến thể; nếu có sẽ được kiểm tra khi prepare |
| `variant` | `V0`, `V1`, `V1u`, `V2` |
| `family`, `packer` | Thông tin họ và packer |
| `die_status` | V0/V1u thật bắt buộc `clean`; V1/V2 thật bắt buộc `packed`; `unknown` không được đưa vào ảnh nghiên cứu |
| `status` | `ok` để được prepare; trạng thái khác được giữ làm audit và loại khỏi train |
| `synthetic` | `0` cho nghiên cứu thật; `1` chỉ dành cho demo |
| `split` | Để trống toàn bộ để tự chia; hoặc tự ghi `train`/`val`/`test` cho toàn bộ dòng |

Không trộn mẫu thật và giả lập. Mỗi parent chỉ có một dòng cho mỗi variant, mọi biến thể cùng nhãn và split. Không được gán cùng bytes cho hai parent khác nhau.

V1 phải ghi packer UPX; V2 phải dùng packer khác. Khi nhập V2 bằng lệnh `variants`, kết quả DiE cũng phải khớp tên `--v2-packer` (trừ khi để tên tổng quát `external`) và không được là UPX.

### 4.4. Tạo ảnh 256×256, chia tập và audit

```powershell
.\.venv\Scripts\python.exe -m byteplot prepare --manifest data/variants-with-v2/manifest.csv --out data/prepared --height 256 --width 256 --window 256 --step 64 --seed 17

.\.venv\Scripts\python.exe -m byteplot audit --manifest data/prepared/prepared.csv --source-manifest data/variants-with-v2/manifest.csv --out runs/data-audit
```

Nếu chưa có V2, thay đường dẫn nguồn bằng `data/variants/manifest.csv`; E5 sau đó sẽ được ghi là bỏ qua do thiếu dữ liệu.

Các lựa chọn đã triển khai:

- Split mặc định **70% train / 15% validation / 15% test**, phân tầng theo nhãn ở cấp parent. Làm tròn và giữ tối thiểu một parent mỗi lớp ở val/test; cần ít nhất 3 parent mỗi lớp để tạo split.
- Đọc prefix `height × width` byte; mỗi byte giữ đúng một vị trí pixel, không resize. Phần thiếu được đệm 0 và có valid-byte mask.
- Entropy chỉ tính từ prefix mà grayscale nhìn thấy. Cửa sổ chồng lấn được lấy trung bình, thêm cửa sổ kết thúc đúng byte cuối để phủ biên; cửa sổ file ngắn chỉ dùng byte thật. Chuẩn hóa entropy theo `/8`, grayscale theo `/255`.
- Nhãn PE: `0` chưa xác định, `.25` header, `.5` section, `.75` stub heuristic, `1` overlay. Stub heuristic là section có tên gợi ý UPX/MPRESS/ASPack và chứa entrypoint; không phải ground truth byte của stub.
- Mẫu lỗi được ghi trong `prepare_errors.csv`. Split được gán trước khi parse ảnh để lỗi một biến thể không làm chuyển parent sang tập khác.
- `prepared.csv` không giữ đường dẫn binary; `features/*.npz` chứa `x` dạng `(3,H,W)` và `mask` dạng `(1,H,W)`. Đây khác với vector `bodmas.npz` của BODMAS.

Kiểm tra `dataset.json`, `prepare_errors.csv`, `runs/data-audit/data_quality.json` và kết quả artifact trước khi chạy lớn. E0 dùng logistic regression với log kích thước, số section và cờ có certificate để phát hiện khác biệt nguồn. Cờ certificate không xác minh chữ ký số hợp lệ. Chương trình không tự cân bằng kích thước hoặc xóa chữ ký; nếu cần xử lý artifact, nhóm phải tạo phiên bản dữ liệu mới và báo cáo thay đổi.

Chỉ chuyển **thư mục `data/prepared/` và source code** sang Colab; không chuyển `data/raw/`, `data/variants*/bytes/` hay binary malware. Nhật ký audit dạng CSV có thể chuyển sau khi kiểm tra nội dung theo quy định của nhóm.

## 4.5. Read-only PE audit for existing BODMAS candidates (Ubuntu VM)

Run from the repository directory inside the isolated Ubuntu VM. This command
reads existing extracted files only. It does not download, extract, restore,
execute, pack or unpack samples; it does not recreate V0/pilot manifests or splits.

For the existing CSV, zip_member contains altered/<original-sha>.exe.
If those files are under /srv/bodmas-disarmed/altered/, use its parent as binary-root:

~~~bash
.venv/bin/python -m byteplot audit-pe \
  --manifest /srv/BODMAS_G2/bodmas_pilot_10_pe_candidates.csv \
  --binary-root /srv/bodmas-disarmed \
  --out runs/e0-pe-pilot-10.csv \
  --height 256 --width 256
~~~

Replace the two /srv paths with the actual locations already present in your VM.
Do not pass a ZIP archive. zip_found=True does not establish file readability or
PE validity. For another CSV with a relative path column, add --path-column path.
Absolute paths, parent traversal and symlinks escaping binary-root are rejected.

If the trusted DiE CLI is installed at /usr/local/bin/diec, choose a new output:

~~~bash
.venv/bin/python -m byteplot audit-pe \
  --manifest /srv/BODMAS_G2/bodmas_pilot_10_pe_candidates.csv \
  --binary-root /srv/bodmas-disarmed \
  --out runs/e0-pe-pilot-10-die.csv \
  --die /usr/local/bin/diec --timeout 120
~~~

DiE is the only external tool: --version records its version and -j performs the
static scan. Its executable must be outside binary-root. Optionally add
--die-db-id <version-or-commit> to record the database ID you have checked;
the executable version does not automatically identify the signature database.
Without DiE, die_tool_status=not_run and die_status=unknown. Errors, timeouts and
unrecognized JSON never become clean. clean means no packer/protector was found
among recognized typed detections, not proof that a sample is unpacked or safe.

Source columns, including sha256, parent_sha256, group and variant, are preserved.
parent_sha256 remains the original identity; disarmed_sha256 hashes the bytes
actually read. Different values do not by themselves mean corruption. Only the
optional expected_disarmed_sha256 column is treated as a content-hash expectation;
disarmed_hash_check is match/mismatch when provided, otherwise unverified.
identity_status=valid checks parent syntax only, not provenance.

One output CSV record is written for every input record, in order, including
duplicate parents, missing files, non-PE files and parser errors.

| Group | Output columns |
| --- | --- |
| Provenance | audit_row, manifest_sha256, preserved source columns, resolved_path, file_status, error |
| Content | disarmed_sha256, disarmed_hash_check, actual_size, size_matches_manifest |
| PE | pe_status, pe_error, parse_warnings, structure_warnings |
| Sections | section_count, declared_sections, sections: JSON with raw offset/size/end, virtual address/size, bounds and visible bytes |
| Overlay | overlay_offset, overlay_size, visible_overlay_bytes; empty offset means no overlay |
| Architecture | machine, architecture, subsystem, pe_format; the original Machine is not inferred from a disarmed header |
| Header observations | disarm_header_hint records Machine=0 AND Subsystem=0, not proof of disarm/safety; certificate_present does not validate a signature |
| Truncation | height, width, capacity_bytes, visible_bytes, truncated, visible_fraction, padding_fraction |
| DiE | die_status, die_tool_status, die_packer, die_error, exit code, stdout/stderr, executable/version and database ID |

parse_warnings, structure_warnings and sections contain JSON. Count records with
a CSV reader, as tool stdout/stderr can contain newlines. Sizes and truncation use
the actual file contents. Missing/unreadable files have empty content measurements.

Output must be outside binary-root and is opened exclusively: an existing output
is an error, with no overwrite switch. Exit code 0 means the report was written,
not that every candidate passed. Review file_status, pe_status, hash checks and
warnings before a later step. This report is not a training manifest for prepare:
the main pipeline's V0 hash contract, CNN and E0-E5 recipes remain unchanged.
This audit gives no evidence of packing success, classifier performance or H1-H4.

## 5. Chạy thí nghiệm nghiên cứu

Ví dụ đầy đủ (cần dữ liệu thật đủ lớn):

```powershell
.\.venv\Scripts\python.exe -m byteplot suite --manifest data/prepared/prepared.csv --source-manifest data/variants-with-v2/manifest.csv --out runs/research-v1 --epochs 20 --batch-size 16 --seeds 17 37 73 --fractions 0.1 0.25 0.5 1.0 --bootstrap 500 --device auto
```

`20` epoch là lựa chọn khởi đầu để chạy, không phải thông số được đề bài chứng minh tối ưu. Chốt cấu hình bằng validation, giữ cùng thiết lập cho các kênh, rồi mới báo cáo test. Suite đầy đủ train nhiều model; có thể chạy từng phần vào các output riêng:

```powershell
.\.venv\Scripts\python.exe -m byteplot suite --manifest data/prepared/prepared.csv --out runs/e3-only --experiments E3 --epochs 20 --seeds 17 37 73 --fractions 0.1 0.25 0.5 1.0
```

| Thí nghiệm | Recipe đã triển khai |
| --- | --- |
| E0 | Audit split/nhãn/DiE, truncation, padding, độ phủ cặp; thống kê thất bại theo packer/nhãn/variant nếu truyền source manifest; baseline artifact |
| E1 | Train C1 trên V0; đánh giá V0/V1/V2 và V1u nếu có. B1 chính là model đó dự đoán V1u; có đánh giá riêng trên giao các parent đủ V0/V1/V1u |
| E2 | C1–C4 train trên V0+V1, validation V0+V1; so sánh trên cùng V1 test |
| E3 | C1/C2 train trên V0+V1 ở các tập con parent lồng nhau, phân tầng nhãn; test cố định. Probe train trên V0+V1, chọn checkpoint bằng MSE validation |
| E4 | Lấy parent có đủ V0/V1, cân bằng số parent hai lớp trong train/val; điều kiện hiếm chỉ giữ 10% benign V1 **trong train** (làm tròn lên, ít nhất một). Validation cân bằng và test giữ nguyên giữa hai điều kiện cùng seed; báo cáo số mẫu thực tế trong selected CSV |
| E5 | C1–C4 train/validation chỉ V1; so sánh trên V2 test, không dùng V2 để chọn checkpoint |

Recipe E2/E4 là lựa chọn triển khai cụ thể cho các phần PDF chưa chốt. Class weight theo tần suất nhãn được bật mặc định cho mọi classifier; có thể tắt đồng nhất bằng `--no-class-weight`. Mọi classifier đều dùng Adam, checkpoint tốt nhất theo Macro-F1 validation và ngưỡng dự đoán cố định `0.5`.

Mọi classifier xuất dự đoán cho tất cả biến thể có trong **test** để tiện đối chiếu; việc đó không đưa các biến thể này vào train/validation. `selected_train.csv`/`selected_val.csv` là bằng chứng về tập dùng để fit/chọn model.

Đối với E4, `selected_val.csv` của balanced và rare_benign_packed phải giống hệt nhau khi cùng seed; `selected_train.csv` chỉ khác ở các dòng benign V1 bị bỏ. Danh sách mẫu trong `predictions.csv` cũng phải giống nhau giữa hai điều kiện, dù xác suất và dự đoán có thể khác. `suite.json` ghi rõ tỉ lệ giữ benign packed của train và validation. Tham số CLI `train --benign-packed-keep` cũng chỉ tác động training.

Metric:

- Macro-F1 cố định hai nhãn `[0,1]`; confusion matrix theo thứ tự `[0,1]`.
- F1 CI 95%: percentile bootstrap theo parent, phân tầng nhãn, giữ các biến thể cùng parent trong một cluster. CI này điều kiện trên model đã train; độ dao động giữa seed được báo cáo riêng bằng trung bình và sample SD.
- FPR của benign từng variant và khoảng tin cậy Wilson 95%; không có benign thì trả `null`, không gán FPR bằng 0.
- Tỉ lệ lật nhãn gồm cả `số đúng→sai / tất cả cặp` và `số đúng→sai / số cặp đúng ở V0`, kèm mẫu số.
- McNemar hai phía chính xác trên cùng mẫu, tách theo seed; kiểm tra correctness, không kiểm định trực tiếp F1. Các p-value là so sánh thăm dò, chưa hiệu chỉnh nhiều kiểm định.
- Probe: MSE trên entropy chuẩn hóa `/8`, MSE quy về đơn vị bit bình phương, Pearson correlation trên pixel hợp lệ; tương quan không xác định trả `null`.
- Learning curve: F1 C1/C2 trên V1, trung bình và SD qua seed; `comparisons.json` có chênh lệch gap giữa mức dữ liệu thấp nhất/cao nhất.

`REPORT.md` tách ba bảng để giữ đúng nguồn số liệu:

- **E2:** C1–C4 train/validation V0+V1. Cột V2 nếu có chỉ là kết quả chẩn đoán của E2, được ghi rõ `diagnostic`.
- **E5:** C1–C4 train/validation chỉ V1 (UPX), test V2 (packer khác). Chỉ lấy kết quả từ run E5; khi chưa chạy E5, báo thiếu kết quả, không lấy V2 của E2 để thay.
- **B1:** C1 của E1 train V0, đánh giá V1u sau unpack tĩnh. Cột V1 của B1 ghi F1 trên V1u; V2 là N/A. Đối chiếu thêm tập cặp khớp của E1 khi đánh giá mức khôi phục.

`central_table.csv` giữ các cột `seed`, `channel`, `train_variants`, `V0`, `V1`, `V2` và bổ sung cột **`experiment`** để phân biệt E2/E5/E1. Dòng E5 chỉ điền V2, để trống V0/V1; B1 nằm ở E1. `results.csv` vẫn giữ kết quả từng run/variant, bao gồm các kết quả chẩn đoán. Bảng **Mean and seed variation** có đúng 8 cột: Experiment, Channel, Condition, Fraction, Variant, Seeds, Mean F1, Sample SD; cách tính trung bình và SD không đổi.

Các lệnh CLI cũ giữ nguyên. Output lịch sử trong `demo-output/` được giữ nguyên để không sửa số liệu đã lưu. Kết quả E4 tạo trước bản sửa cần chạy lại vào thư mục mới vì validation trước đây đã bị giảm ở điều kiện rare; chỉ đổi cách trình bày báo cáo không sửa được vấn đề đó. Bản demo kiểm tra sau sửa dùng `runs/review-demo/`, xem [REPORT mới](runs/review-demo/runs/REPORT.md) và [biên bản kiểm tra](REVIEW.md). Chạy lại tương đương với output mới:

```powershell
.\.venv\Scripts\python.exe -m byteplot demo --out runs/review-demo-new --epochs 1
```

## 6. Train trên Colab

Upload source code (`byteplot/`, `requirements.txt`) cùng **thư mục ảnh/feature đã chuẩn bị**, mở notebook ở thư mục dự án. Bật GPU nếu có. Colab thường đã có PyTorch; không chạy script cài CPU của Windows ở đây.

```python
%pip install -r requirements.txt
!python -m byteplot suite --manifest data/prepared/prepared.csv --out runs/colab-e3 --experiments E3 --epochs 20 --seeds 17 37 73 --fractions 0.1 0.25 0.5 1.0 --device auto
```

Nếu hết VRAM, giảm `--batch-size` đồng nhất cho các cấu hình. Sao lưu thư mục `runs/` vì phiên Colab có thể kết thúc. Checkpoint chỉ lưu model/cấu hình phục vụ đánh giá, chưa hỗ trợ resume optimizer giữa chừng; để chạy lại dùng output mới.

## 7. Kiểm thử và cấu trúc code

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q byteplot tests
.\.venv\Scripts\python.exe -m byteplot --help
```

Các kiểm thử kiểm tra entropy với phân bố biết trước, căn chỉnh byte/pixel, nhãn vùng PE từ header fixture, chia tập và tập con parent lồng nhau, lỗi hash/rò rỉ, padding loss, metric cặp, nhận diện JSON DiE, huấn luyện C1–C4/probe và nạp lại checkpoint.

Regression test trong `tests/test_regressions.py` bổ sung kiểm tra nguồn E5 (có cả suite chỉ chạy E5 và trường hợp chưa chạy E5), B1, số cột của mọi bảng Markdown, giá trị mean/sample SD, và E4 trên hai seed với đối chiếu CSV train/validation/test cùng kiểm tra parent không rò rỉ. Số điểm giả định trong unit test chỉ là fixture để phát hiện gán nhầm nguồn, không phải số liệu nghiên cứu.

```text
byteplot/
  cli.py             # Các lệnh chạy
  io.py              # Manifest, kiểm tra rò rỉ, split và tập con
  vm_tools.py        # Index bằng DiE; UPX V1/V1u; nhập V2
  representation.py  # Grayscale, entropy, vùng PE, mask
  synthetic.py       # Dữ liệu giả lập không thực thi
  models.py          # CNN 3 khối và entropy probe
  engine.py          # Train, checkpoint, predict
  metrics.py         # F1, CI, FPR, lật nhãn, McNemar
  experiments.py     # Recipe E0–E5
  report.py          # Bảng và hình xuất ra file
tests/
scripts/
examples/
```

Chưa bao gồm B2 LightGBM (phần tùy chọn của đề), tải dữ liệu có kiểm soát truy cập, tự tạo V2 bằng MPRESS/ASPack, hoặc kết quả nghiên cứu trên malware thật. Các phần này cần dữ liệu/công cụ trong VM và lựa chọn thực nghiệm của nhóm.

API tham khảo cho phần triển khai: [PyTorch Conv2d](https://docs.pytorch.org/docs/2.9/generated/torch.nn.Conv2d.html), [nạp checkpoint với `weights_only`](https://docs.pytorch.org/docs/2.9/generated/torch.load.html), [SciPy binomial test](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.binomtest.html), [pefile PE parser](https://pefile.readthedocs.io/en/latest/modules/pefile.html), [tài liệu UPX](https://github.com/upx/upx/blob/devel/doc/upx.pod).
