# Group 6 — Entropy có dư thừa với CNN byteplot dưới packing?

**Môn học:** IAM302t  
**Mục đích README:** mô tả những việc nhóm cần làm theo tài liệu hướng dẫn, làm cơ sở triển khai và kiểm tra trước khi nộp. Các mục bên dưới là yêu cầu và kế hoạch nghiên cứu, chưa phải báo cáo kết quả.

**Code đã triển khai:** pipeline Python/PyTorch trong `byteplot/`, có demo dữ liệu giả lập, tạo kênh ảnh, C1–C4, baseline B1 qua V1u, probe, learning curve, E0–E5 và báo cáo. Xem **[hướng dẫn cài đặt và chạy thử](RUNNING.md)**. Kết quả demo không phải bằng chứng nghiên cứu trên malware thật.

```powershell
.\.venv\Scripts\python.exe -m byteplot demo --out demo-my-run --epochs 1
```

**Tài liệu nguồn:** [Hướng dẫn hướng đi — Entropy có dư thừa Kênh phụ cho CNN byteplot (Group 6, IAM302t).pdf](<Hướng dẫn hướng đi — Entropy có dư thừa Kênh phụ cho CNN byteplot (Group 6, IAM302t).pdf>) — 9 trang. Các mục bên dưới tóm tắt yêu cầu trong PDF; những lựa chọn triển khai chưa được tài liệu quy định được đánh dấu riêng.

## 1. Mục tiêu đề tài

Kiểm tra xem **kênh entropy có cung cấp giá trị bổ sung cho CNN phân loại benign/malware từ ảnh byteplot khi file bị pack hay không**, hay chỉ giúp mô hình học nhanh hơn thông tin vốn đã có trong các byte đầu vào.

So sánh thêm với **kênh nhãn vùng PE** để đánh giá vai trò của thông tin cấu trúc. Entropy được tính từ byte cục bộ, trong khi nhãn vùng PE cần phân tích cấu trúc file. Không chỉ dừng ở câu hỏi “CNN hai kênh có tốt hơn một kênh không”.

Phạm vi theo đề: PE Windows, đặc trưng tĩnh, ảnh byteplot, UPX và một packer khác cho thí nghiệm tổng quát hóa; CNN nhỏ có thể train trên Colab miễn phí; không phân tích động. *(PDF, trang 1–2)*

## 2. Câu hỏi nghiên cứu và giả thuyết

| Mã | Cần trả lời | Bằng chứng cần thu |
| --- | --- | --- |
| RQ1 | UPX làm CNN một kênh suy giảm bao nhiêu? Unpack tĩnh khôi phục được bao nhiêu? | Macro-F1 theo biến thể; tỉ lệ lật nhãn trên cặp; baseline unpack tĩnh |
| RQ2 | Entropy có dư thừa với ảnh grayscale không? | Learning curve C1/C2; probe dự đoán entropy từ grayscale |
| RQ3 | Nhãn vùng PE có giúp nhiều hơn entropy không? | So sánh C1, C2, C3, C4 trên cùng tập đánh giá |
| RQ4 | Kênh entropy giúp hay làm tăng báo động nhầm trên benign packed? | FPR benign packed, có/không entropy |

Các giả thuyết cần kiểm chứng:

- **H1:** packing làm F1 giảm; unpack tĩnh khôi phục gần hết với UPX.
- **H2:** entropy giúp khi ít dữ liệu, nhưng chênh lệch C2 − C1 thu hẹp khi tăng dữ liệu; probe có thể dự đoán entropy tốt.
- **H3:** kênh nhãn vùng PE giúp nhiều hơn kênh entropy.
- **H4:** entropy có thể làm tăng FPR trên benign packed vì làm đặc điểm packing nổi bật hơn.

Đây là **giả thuyết, không phải kết quả có sẵn**. Nếu entropy vẫn giúp bền vững hoặc probe dự đoán kém, nhóm vẫn phải báo cáo trung thực. *(PDF, trang 2, 6)*

## 3. Đọc tài liệu liên quan

- [ ] Đọc Nataraj et al., *Malware Images*, VizSec 2011: nền tảng biểu diễn byteplot.
- [ ] Đọc Aghakhani et al., *When Malware is Packin’ Heat*, NDSS 2020: ảnh hưởng và shortcut liên quan đến packing.
- [ ] Tìm và đọc các công trình CNN hai kênh / ảnh malware bổ sung entropy.
- [ ] Đối chiếu bản gốc, ghi trích dẫn đầy đủ và nêu rõ điểm khác của nhóm: kiểm tra tính dư thừa của entropy và so với thông tin cấu trúc PE.

*(PDF, trang 1, 8)*

## 4. Chuẩn bị dữ liệu và thiết kế cặp

### 4.1. Nguồn dữ liệu

| Nguồn | Công việc |
| --- | --- |
| BODMAS binary malware | Nguồn malware chính; gửi yêu cầu truy cập sớm nếu chưa có binary |
| MalwareBazaar | Nguồn dự phòng hoặc bổ sung binary |
| Benign tự thu | Thu PE hợp lệ từ Windows, phần mềm trên trang chính thức hoặc kho gói |
| MalImg | Không dùng cho pipeline này: chỉ có ảnh, không có binary để tạo cặp tự pack |
| EMBER dạng vector đặc trưng | Không dùng để dựng ảnh byteplot và tạo cặp packing |

**Tình trạng thư mục hiện tại:** có thư mục `drive-download-20261015T055410Z-1-001/` chứa README BODMAS, metadata, `bodmas.npz`, file ZIP vector đặc trưng và các file hỗ trợ disarm. Chưa thấy kho binary malware hoặc bộ benign trong danh sách file hiện có. Vector `.npz` không thay thế được binary cho việc pack và dựng ảnh byteplot.

README đi kèm BODMAS mô tả dữ liệu gốc và cách khôi phục mẫu. Pipeline hiện tại không tự chạy script khôi phục; giai đoạn chuẩn bị binary thật thực hiện riêng trong VM theo yêu cầu an toàn bên dưới.

### 4.2. Bốn nhóm dữ liệu

| Nhóm | Cách tạo |
| --- | --- |
| Benign unpacked | PE hợp lệ chưa phát hiện packing |
| Benign packed | Bản tự pack từ benign unpacked; có thể bổ sung benign pack sẵn ngoài đời nếu thu được |
| Malware unpacked | Malware đã lọc bỏ mẫu bị phát hiện pack/protect sẵn |
| Malware packed | Bản tự pack từ malware unpacked |

- Chạy **Detect It Easy (DiE)** trên mọi mẫu gốc; loại mẫu đã phát hiện pack/protect khỏi nhóm unpacked và ghi số lượng loại.
- Mục tiêu **1.000–2.000 mẫu mỗi nhóm**, tối thiểu **800 mẫu mỗi nhóm** theo hướng dẫn.
- Chuẩn bị đủ mẫu để lấy các tập con cho learning curve.

### 4.3. Các biến thể cần tạo

| Mã | Biến thể | Mục đích |
| --- | --- | --- |
| V0 | Bản gốc đã qua lọc packing | Mốc so sánh unpacked |
| V1 | V0 được pack bằng UPX | Đo suy giảm do packing và giá trị kênh phụ |
| V1u | V1 được unpack tĩnh bằng `upx -d` | Đầu vào cho baseline B1 |
| V2 | V0 được pack bằng packer khác, ví dụ MPRESS hoặc ASPack | Đánh giá packer chưa gặp, nhất là E5 |

Trong bảng này, “bản sạch” V0 nghĩa là bản chưa bị biến đổi bằng packer của thí nghiệm; V0 vẫn có thể mang nhãn malware.

Giữ **`parent_sha256`** để liên kết mọi biến thể với cùng mẫu gốc. Ghi kết quả pack/unpack, tỉ lệ thất bại theo packer và nhóm; chú ý khả năng thất bại lệch ở file .NET. Dùng DiE để kiểm tra V1/V2. Không âm thầm loại mẫu thất bại khỏi báo cáo.

### 4.4. Manifest và chia tập

Manifest phải có: **hash, họ malware, nhóm, packer, `parent_sha256`, kết quả DiE, tập dữ liệu**. Nên bổ sung tên biến thể và trạng thái pack/unpack để truy vết thí nghiệm.

- Chia train/validation/test **theo mẫu gốc**: tất cả biến thể cùng `parent_sha256` phải nằm trong cùng một tập.
- Giữ phân bố bốn nhóm phù hợp khi chia; không chia ngẫu nhiên độc lập từng ảnh/biến thể.
- Kiểm tra không trùng mẫu gốc giữa các tập. Bản packed của mẫu test không được xuất hiện trong train.
- Tài liệu không bắt buộc temporal split, nhưng vẫn bắt buộc chống rò rỉ giữa các biến thể.
- Giữ nguyên tập test khi thay đổi lượng dữ liệu train cho learning curve.

*(PDF, trang 2–3)*

## 5. Xây dựng ảnh và các kênh đầu vào

### 5.1. Ba loại kênh

| Kênh | Cần triển khai |
| --- | --- |
| Grayscale byteplot | Ánh xạ 1 byte thành 1 pixel mức xám |
| Entropy map | Entropy Shannon theo cửa sổ **256 byte**, bước **64 byte**, trải giá trị về vị trí byte tương ứng |
| Nhãn vùng PE | Dùng `pefile` phân tích và gán byte vào header / section / stub packer / overlay, mã hóa bằng mức xám |

Entropy Shannon: `H = -Σ p(b) × log2(p(b))`, với `p(b)` là tần suất tương đối của byte trong cửa sổ; bỏ các phần tử có xác suất 0.

Các yêu cầu về biểu diễn:

- Dùng chiều rộng cố định, cắt/đệm để có kích thước ảnh cố định.
- Giữ ánh xạ **pixel → offset byte** để các kênh khớp nhau.
- Báo cáo tỉ lệ file bị cắt.
- Kiểm soát zero-padding: thêm mask vùng đệm hoặc ghi nhận padding như một biến kiểm soát.
- Tạo hình minh họa grayscale, entropy và nhãn vùng PE giữa bản unpacked/packed.

**Lựa chọn triển khai cần chốt và ghi lại:** kích thước ảnh; cách gộp các cửa sổ entropy chồng lấn và xử lý biên; quy tắc nhận diện stub packer và mã hóa nhãn PE; chuẩn hóa kênh; cách dùng mask. PDF chưa quy định đầy đủ các chi tiết này. Nếu thêm mask vào input, phải mô tả rõ số kênh thực tế và áp dụng nhất quán giữa các cấu hình.

### 5.2. Bốn cấu hình phải so sánh

| Cấu hình | Đầu vào |
| --- | --- |
| **C1** | Grayscale — 1 kênh, baseline chính |
| **C2** | Grayscale + entropy — 2 kênh |
| **C3** | Grayscale + nhãn vùng PE — 2 kênh |
| **C4** | Grayscale + entropy + nhãn vùng PE — 3 kênh |

*(PDF, trang 3–4)*

## 6. Model, baseline và huấn luyện

- Dùng custom CNN nhỏ khoảng **3–4 khối convolution**, phù hợp Colab miễn phí.
- C1–C4 dùng cùng kiến trúc, chỉ thay đổi số kênh đầu vào để so sánh giá trị kênh phụ.
- Giữ cùng số epoch và bộ tối ưu; chọn checkpoint theo F1 trên validation.
- Validation chỉ chứa những biến thể mà thiết lập huấn luyện đó được phép thấy. Với E5, không dùng V2 để chọn model.
- Chạy **3 seed**; lưu cấu hình, seed, checkpoint và kết quả để tái lập.
- Nếu mất cân bằng, dùng class weight hoặc oversampling thông thường; không cần GAN.

| Baseline | Yêu cầu |
| --- | --- |
| C1 grayscale | Bắt buộc, mốc chính để tính lợi ích kênh phụ |
| **B1 unpack tĩnh** | **Bắt buộc:** unpack V1 thành V1u, sau đó phân loại bằng C1; đánh giá mức khôi phục so với V0/V1 |
| B2 đặc trưng tĩnh | **Tùy chọn:** LightGBM trên đặc trưng kiểu EMBER trích từ binary |

Với V2, báo cáo giới hạn của baseline unpack UPX; nếu không unpack được thì ghi rõ, không điền một giá trị F1 giả định. *(PDF, trang 4–5)*

## 7. Thực hiện các thí nghiệm E0–E5

| Mã | Việc cần làm | Đầu ra cần có |
| --- | --- | --- |
| **E0 — Kiểm tra dữ liệu** | Thống kê pack thất bại; xác nhận V1/V2 bằng DiE; kiểm tra artifact nguồn bằng model chỉ dùng kích thước, số section, chữ ký số | Bảng chất lượng dữ liệu; kết quả kiểm tra artifact; giải thích nếu artifact mạnh |
| **E1 — Suy giảm** | Train trên V0, test trên V0/V1/V2; so với B1 unpack tĩnh | Macro-F1 theo biến thể; tỉ lệ lật nhãn theo cặp |
| **E2 — Kênh phụ** | So sánh C1/C2/C3/C4 trên mẫu packed với điều kiện huấn luyện tương đương | Bảng F1 và chênh lệch giữa các cấu hình |
| **E3 — Entropy dư thừa** | Learning curve C1/C2 và probe entropy | Biểu đồ F1 theo lượng dữ liệu; MSE/tương quan probe |
| **E4 — Shortcut** | So sánh điều kiện benign packed hiếm với cân bằng; có/không entropy | FPR benign packed và khoảng tin cậy Wilson |
| **E5 — Packer chưa gặp** | Train các cấu hình kênh phụ trên V1 (UPX), test V2 | Kết quả tổng quát hóa sang packer khác |

**Điểm cần chốt khi lập cấu hình:** PDF chưa ấn định đầy đủ tỉ lệ split, thành phần train cho E2, hay tỉ lệ benign packed “hiếm” trong E4. Nhóm phải ghi rõ các lựa chọn này, giữ điều kiện so sánh công bằng và không dùng test để chọn cấu hình.

### E3 là phần cốt lõi, gồm hai việc riêng

**A. Learning curve**

1. Tạo các tập con **10%, 25%, 50%, 100%** của train; giữ thiết kế chia theo mẫu gốc.
2. Train C1 và C2 trên cùng tập con ở từng mức; **3 seed mỗi mức**.
3. Đánh giá trên cùng tập test; vẽ Macro-F1 trên mẫu packed theo lượng dữ liệu.
4. So sánh khoảng cách C2 − C1 ở 10% với 100% dữ liệu.

**B. Probe dự đoán entropy**

1. Xây CNN nhỏ nhận grayscale và xuất entropy map dự đoán.
2. Huấn luyện bằng loss MSE với entropy map thật làm mục tiêu.
3. Đánh giá MSE và/hoặc tương quan trên test; hướng dẫn yêu cầu báo cáo tương quan probe.
4. Đối chiếu kết quả probe với learning curve và so sánh C2/C3 để trả lời RQ2–RQ3.

Gợi ý triển khai: khi tính sai số probe, xử lý vùng padding rõ ràng để kết quả không bị chi phối bởi phần đệm.

*(PDF, trang 4–6)*

## 8. Metric và cách trình bày kết quả

| Metric | Cần báo cáo |
| --- | --- |
| **Macro-F1** | Chỉ số chính; không chỉ dùng accuracy khi mất cân bằng |
| **Tỉ lệ lật nhãn theo cặp** | Các cặp được dự đoán đúng ở bản unpacked nhưng sai ở bản packed |
| **Chênh lệch kênh phụ** | `F1(C2/C3/C4) − F1(C1)` trên mẫu packed |
| **Tương quan probe** | Giữa entropy dự đoán và entropy thật |
| **Độ thu hẹp learning curve** | So sánh `(F1(C2) − F1(C1))` ở mức train 10% và 100% |
| **FPR benign packed** | Số benign packed bị dự đoán malware / tổng benign packed; kèm khoảng tin cậy Wilson |

Tài liệu mô tả sự kiện lật nhãn nhưng chưa chốt rõ mẫu số. Nhóm cần ghi rõ cách tính khi triển khai; nên kèm số cặp đánh giá và số cặp đúng ở V0 để người đọc hiểu kết quả.

Yêu cầu độ tin cậy: **3 seed, F1 kèm khoảng tin cậy**, so C1/C2 và C2/C3 trên cùng mẫu bằng **McNemar**. Ghi rõ cách tính khoảng tin cậy F1; không nhầm kiểm định McNemar với kiểm định trực tiếp chênh lệch F1.

Bảng kết quả trung tâm cần điền sau khi chạy thí nghiệm:

| Cấu hình | F1 V0 | F1 V1 — UPX | F1 V2 — packer chưa gặp |
| --- | --- | --- | --- |
| C1 grayscale | Chưa đo | Chưa đo | Chưa đo |
| C2 + entropy | Chưa đo | Chưa đo | Chưa đo |
| C3 + vùng PE | Chưa đo | Chưa đo | Chưa đo |
| C4 cả hai | Chưa đo | Chưa đo | Chưa đo |
| B1 unpack tĩnh | Chưa đo | Chưa đo trên V1u | Ghi rõ khả năng/giới hạn unpack |

Khi kết luận, nêu cụ thể entropy giúp bao nhiêu điểm F1 khi ít/đủ dữ liệu, probe tốt đến đâu và kênh vùng PE giúp bao nhiêu. Không mặc định H1–H4 đúng. Kết luận về tính dư thừa phải gắn với kiến trúc, dữ liệu và packer đã thử. *(PDF, trang 6–7)*

## 9. An toàn, rủi ro và giới hạn

Các yêu cầu an toàn dưới đây được tóm tắt từ đề bài và áp dụng cho giai đoạn xử lý binary:

- Pack/unpack, parse PE và tạo ảnh trong VM riêng; Linux cho UPX/`pefile`, Windows cho MPRESS/ASPack; không có thư mục chia sẻ ghi được.
- Không thực thi, mở/nhấp đúp hoặc giải nén mẫu malware trên máy cá nhân. Nếu cần tắt antivirus, chỉ thực hiện trong VM theo hướng dẫn.
- Chỉ đưa **ảnh, feature và manifest** ra khỏi VM; chỉ upload ảnh/feature lên Colab, không upload binary malware.
- Mẫu trong ZIP có mật khẩu; không phát hành file đã pack, kể cả benign packed. Dữ liệu công bố chỉ gồm ảnh/feature, hash và script.
- Có mục đạo đức và an toàn trong báo cáo.

Rủi ro cần theo dõi và giải thích:

- Không lấy được BODMAS binary: gửi yêu cầu sớm và chuẩn bị MalwareBazaar dự phòng.
- Artifact nguồn mạnh: kiểm tra bằng E0; cân bằng kích thước hoặc xử lý overlay chữ ký theo hướng dẫn, ghi rõ các thay đổi dữ liệu.
- Pack thất bại lệch theo họ/.NET: thống kê riêng và cân nhắc bổ sung mẫu không phải .NET.
- Rò rỉ biến thể: kiểm tra hash và `parent_sha256` giữa các tập.
- Probe khó hội tụ hoặc thiếu mẫu learning curve: báo cáo trung thực; có thể giảm số mức learning curve nếu cần và nêu lý do.
- Mẫu tự pack khác crypter thực tế; “unpacked” chỉ có nghĩa chưa bị phát hiện packing; quy mô vài nghìn mẫu và khác biệt nguồn giới hạn khả năng khái quát.

*(PDF, trang 6–7)*

## 10. Phân công và lộ trình 8 tuần

Nhóm tự gán tên cho 4 vai trò:

| Vai trò | Phụ trách |
| --- | --- |
| Dữ liệu và an toàn | Xin binary, VM, benign, DiE, pack/unpack, manifest và chia tập |
| Biểu diễn | Byteplot giữ offset, entropy map, nhãn vùng PE, kiểm soát padding |
| Model | CNN C1–C4, B1, probe, lưu cấu hình và checkpoint |
| Đánh giá | Metric, E0–E5, learning curve, biểu đồ, bảng và kiểm định |

| Tuần | Công việc chính | Đầu ra |
| --- | --- | --- |
| 1 | Related work; xin BODMAS; dựng VM; chốt RQ; thu dữ liệu và pack UPX | Tổng quan tài liệu; tập cặp V0/V1 ban đầu |
| 2 | Byteplot giữ offset; chia theo mẫu gốc; C1; E0 | Baseline và kết quả kiểm tra dữ liệu |
| 3 | Entropy map; nhãn vùng PE; hình minh họa packed/unpacked | Các kênh phụ sẵn sàng |
| 4 | Chạy C2/C3/C4 đầu-cuối; E1 và B1 | Bảng suy giảm và tỉ lệ lật nhãn |
| 5 | Train đầy đủ C1–C4; E2 | Bảng so sánh kênh phụ |
| 6 | Probe; learning curve; E3 | Bằng chứng entropy dư thừa hoặc không |
| 7 | E4; E5 với packer khác; hoàn tất 3 seed | FPR benign packed; kết quả tổng quát hóa |
| 8 | Viết báo cáo; đóng gói code và hướng dẫn tái lập | Bản nộp hoàn chỉnh |

**Mốc bắt buộc cần ưu tiên:** cuối tuần 3 có tập cặp V0/V1 đã chia tập và baseline C1 chạy được. *(PDF, trang 8–9)*

## 11. Đầu ra và checklist trước khi nộp

- [ ] Báo cáo đặt đúng trọng tâm: entropy có dư thừa không và CNN thiếu thông tin gì.
- [ ] Related work có Nataraj, Aghakhani và công trình hai kênh/entropy; phân biệt rõ đóng góp.
- [ ] Có binary phù hợp và benign tự thu; không dùng vector `.npz` thay cho byteplot từ binary.
- [ ] Có bốn nhóm dữ liệu, các cặp V0/V1 và V2 cho E5; thống kê DiE và pack/unpack thất bại.
- [ ] Có manifest, `parent_sha256`, danh sách split và kiểm tra chống rò rỉ.
- [ ] Có ảnh giữ offset, entropy map, nhãn vùng PE; báo cáo truncation và xử lý padding.
- [ ] Có C1–C4 và baseline unpack tĩnh B1; B2 chỉ là phần tùy chọn.
- [ ] Có E0–E5, đặc biệt learning curve và probe của E3.
- [ ] Có Macro-F1, tỉ lệ lật nhãn, chênh F1, tương quan probe và FPR benign packed.
- [ ] Có 3 seed, khoảng tin cậy F1, Wilson cho FPR và so sánh McNemar theo yêu cầu.
- [ ] Có bảng kết quả trung tâm, biểu đồ learning curve và minh họa các kênh.
- [ ] Kết luận dựa trên số đo thực tế, chấp nhận cả hai khả năng entropy dư thừa hoặc vẫn hữu ích.
- [ ] Báo cáo có an toàn, đạo đức, rủi ro và threat to validity.
- [ ] Đóng gói code, manifest, cấu hình, seed và hướng dẫn chạy lại; chỉ chia sẻ dữ liệu được phép theo quy tắc an toàn của đề.

*(PDF, trang 9; chi tiết các đầu ra tổng hợp từ trang 3–8)*
