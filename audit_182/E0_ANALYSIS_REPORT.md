# Phân tích E0 — trạng thái hiện tại ngày 02/11/2026

## Audit và nguồn dữ liệu

Audit static182 có CSV đã bỏ định danh: 182/182 PE parse thành công, 102 DiE clean, 58 packed và 22 unknown; 145/182 vượt giới hạn ảnh 64 KiB. Pilot10 là tập chẩn đoán riêng, không cộng trực tiếp vào static182 hoặc dùng để suy rộng toàn kho BODMAS.

Pilot V0 dùng 50 malware + 50 benign. Tập paired UPX giữ 42 malware + 8 benign có đủ V0/V1/V1u, tổng 150 hàng biến thể; test chỉ có 8 malware và 2 benign. Cả 42 benign Windows của cohort ban đầu bị loại do không tương thích thiết lập UPX tiêu chuẩn. Vì vậy cần xét selection bias và sai lệch nguồn.

## Kết quả và đối chứng đã có

- E0 paired: 150 hàng, 50 parent; 100 clean + 50 packed theo trạng thái biến thể được ghi nhận; 108/150 hàng vượt 64 KiB. Các trạng thái này không chứng minh mọi V0 là unpacked.
- Baseline metadata paired đạt F1 = 0,4444 và FPR = 1 trên 10 parent test. Metadata V0 cũ đạt F1 = 0,75 trên 16 parent thuộc cohort khác; không lấy chênh hai điểm làm ablation.
- Grouped CV, che prefix và baseline Rich/linker đã chạy. Rich/linker đạt Macro-F1 0,9800 trên cohort V0 và folds M1; đây là đối chứng chẩn đoán nguồn, không phải metric CNN hoặc kết quả trên cohort paired.
- Coverage tĩnh đã có 150/150 variant, 0 lỗi. Mỗi variant có 41/50 EP trong prefix; V1 có 9/50 EP ngoài ảnh dù 50/50 có nhãn heuristic. Nhãn section không xác minh ranh giới stub giải nén.
- Báo cáo/code/CSV Group 5 đã được đối chiếu tại mục 2.1 của báo cáo; chưa tái lập Group 5 trên cùng cohort.

## Giới hạn còn lại

M1 chưa tăng số quan sát độc lập hoặc có external holdout; M2 đã được chẩn đoán nhưng chưa kiểm soát nguồn; M3 có 4/12 classifier qua gate, sáu probe và CI theo parent, nhưng lưới classifier matched chưa đầy đủ. Baseline MalConv chưa có kết quả train; V2/E5 chưa chạy. Không khẳng định entropy cải thiện CNN nói chung hoặc FPR thấp ngoài tập test chỉ hai benign.

Nguồn: Static182/static182_audit_redacted.csv; UPX50/; Rich_Linker/; Probe_Parent_CI/; M3_Diagnostics/; Prefix_Coverage/. Báo cáo chính và SUBMISSION_STATUS.md là trạng thái hiện hành; biên nhận lịch sử được giữ nguyên tại thời điểm thực nghiệm.
