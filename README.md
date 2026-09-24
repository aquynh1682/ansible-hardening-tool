# VDI Hardening Scanner

Công cụ web quét và triển khai hardening cho máy chủ Linux theo checklist nội bộ
(phần ảo hoá + 45 mục OS server). Ansible làm engine thực thi, bọc bên ngoài là
web UI để khỏi phải gõ lệnh.

**Không database, không Docker, không framework.** Chỉ Python stdlib + ansible.

```bash
python3 hardening.py --open
```

## Cài đặt

Yêu cầu duy nhất ngoài Python 3.9+ là `ansible-playbook`:

```bash
pip install ansible-core                              # hoặc: apt install ansible
ansible-galaxy collection install -r ansible/requirements.yml
python3 hardening.py                                  # http://127.0.0.1:8000
```

Thêm `sshpass` nếu dùng xác thực bằng mật khẩu (`apt install sshpass` /
`brew install hudochenkov/sshpass/sshpass`). Thanh trạng thái góc phải giao diện
báo thiếu gì.

Mặc định chỉ lắng nghe `127.0.0.1`. Dùng `--host 0.0.0.0` nếu cần máy khác truy cập —
nhưng công cụ **không có xác thực người dùng** và nắm quyền root toàn hệ thống,
nên chỉ làm vậy trong mạng quản trị tin cậy.

## Luồng sử dụng

1. **Cấu hình** — khai báo NTP server nội bộ, dải IP quản trị, user quản trị, log server…
2. **Credential** — thêm SSH key (khai đường dẫn file) hoặc username/password.
3. **Máy chủ** — nhập dải IP (`192.168.1.0/24`, `10.0.0.10-40`, IP đơn, hostname),
   bấm **Dò tìm** → quét cổng SSH và liệt kê host sống.
4. Chọn host (hoặc chọn tất) → gán credential → **Quét đánh giá**.
5. **Kết quả & Report** — bảng PASS / FAIL / WARN / MANUAL / NA cho từng mục kèm
   bằng chứng. Xuất CSV (Excel đọc đúng tiếng Việt) hoặc bản in HTML.
6. **Triển khai** — chọn mục cần khắc phục (hoặc bấm *Khắc phục các mục chưa đạt*
   để chọn tự động) → chạy → công cụ **tự quét lại và sinh report mới**.
7. **Lịch sử** — so sánh hai lần chạy để thấy mục nào đã khắc phục, mục nào xấu đi.

## Dữ liệu lưu ở đâu

Tất cả nằm trong `data/`, là file JSON đọc và sửa được bằng tay:

```
data/
├── settings.json          tham số chuẩn hardening
├── credentials.json       username + đường dẫn key (KHÔNG có mật khẩu)
├── hosts.json             danh sách máy chủ
├── marks.json             các mục tick tay, khoá theo "<ip>|<check_id>"
└── runs/run-<n>/
    ├── meta.json          loại, trạng thái, thời gian, mã lỗi
    ├── run.log            log đầy đủ của lần chạy
    ├── results.json       kết quả đã chuẩn hoá
    └── reports/           JSON thô từng host do agent trả về
```

Muốn xoá lịch sử thì xoá thư mục `data/runs/`. Muốn backup thì copy `data/`.
Sửa `settings.json` bằng editor cũng được, tool đọc lại ở lần chạy sau.

**Mật khẩu SSH không bao giờ được ghi xuống đĩa** — chỉ giữ trong RAM của tiến trình.
Tắt tool đi là mất, lần sau giao diện sẽ hỏi lại trước khi quét. SSH key thì không
bị ảnh hưởng vì chỉ lưu đường dẫn.

## Kiến trúc

```
┌──────────────┐  HTTP + SSE   ┌──────────────────┐   SSH    ┌──────────────┐
│  frontend/   │ ◄───────────► │  hardening.py    │ ───────► │  Host đích   │
│  JS thuần    │               │  stdlib + JSON   │ ansible  │  Ubuntu/RHEL │
└──────────────┘               └──────────────────┘          └──────────────┘
```

| Thành phần | Vai trò |
|---|---|
| `catalog/checklist.json` | **Nguồn chân lý** của 47 tiêu chí: mục đích, yêu cầu mức đạt, mức độ nghiêm trọng, có tự động khắc phục được không |
| `ansible/files/audit_agent.py` | Agent **chỉ đọc**, chạy trên host đích, trả JSON có cấu trúc. Một lượt SSH cho cả 47 mục thay vì 47 lượt |
| `ansible/roles/harden/` | Task khắc phục, mỗi mục một tag (`--tags OS-30`) để chạy riêng lẻ |
| `app/` | HTTP server stdlib, quản lý job, sinh inventory, xuất report |
| `frontend/` | Trang tĩnh, không build, không gọi CDN — chạy được trong mạng air-gap |

Hai quyết định đáng nói:

- **Audit tách khỏi Ansible task.** Audit chỉ cần đọc trạng thái nên gom vào một
  script Python cho nhanh và cho kết quả có cấu trúc. Remediate mới cần Ansible
  thật — idempotent, có handler, validate trước khi ghi đè.
- **Inventory sinh ra dưới dạng JSON** (đặt đuôi `.yml`, vì JSON là YAML hợp lệ).
  Nhờ vậy mật khẩu chứa `"`, `:`, `#`, khoảng trắng đều an toàn, mà không cần PyYAML.
  File inventory và extra-vars bị **xoá ngay sau khi chạy xong** vì có chứa mật khẩu.

## An toàn — những chốt chặn đã cài sẵn

Hardening sai cách có thể khoá mất máy chủ. Các mục rủi ro đều có chốt chặn:

| Mục | Chốt chặn |
|---|---|
| OS-10 Firewall | Luôn mở SSH cho dải IP quản trị **và** cho chính IP của máy chạy Ansible **trước khi** bật ufw. Chưa khai báo dải IP quản trị → bỏ qua cả mục |
| OS-09 Tắt login root | Từ chối chạy nếu không tìm thấy user nào trong group `wheel`/`sudo` |
| OS-27 pam_wheel | Thêm user quản trị vào group `wheel` và xác nhận group có thành viên trước khi bật |
| OS-05 SSH AllowGroups | Bỏ qua nếu chưa khai báo user quản trị |
| OS-06 sudo NOPASSWD:ALL | Chỉ **báo cáo**, không tự xoá — xoá nhầm là mất quyền quản trị |
| OS-07 user UID=0 | Chỉ báo cáo, không tự sửa |
| OS-14 kdump | Chỉ chạy khi bật *Cho phép thay đổi cần reboot*; có cảnh báo phải reboot |
| OS-32 file unowner / OS-33 PATH | Chỉ liệt kê, không tự `chown` hay sửa PATH vì dễ hỏng ứng dụng |
| Mọi thay đổi sshd/sudoers | Ghi ra file drop-in riêng, `validate` bằng `sshd -t` / `visudo -c` trước khi áp dụng |
| Backup | File cấu hình bị sửa đều được backup, thư mục `/var/backups/hardening` trên host |

Quá trình **quét đánh giá không ghi gì** lên host đích. Chạy hardening chỉ đụng
tới sshd khi bạn thực sự chọn mục liên quan SSH (OS-05/09/30).

## Yêu cầu với host đích

- SSH tới được, tài khoản có quyền `sudo`.
- Có `python3` (Ubuntu 18.04 trở lên đều có sẵn).
- Nếu dùng SSH key: key **không đặt passphrase** (tool chạy không tương tác).

## Phân loại 47 tiêu chí

- **30 mục tự động khắc phục được** — có tag Ansible tương ứng.
- **10 mục chỉ audit** — `OS-01` phân vùng, `OS-04` crontab, `OS-07` UID=0,
  `OS-08` app chạy root, `OS-12` bonding, `OS-13` multipath, `OS-17` NetworkManager,
  `OS-32` file unowner, `OS-39` OpenSSL, `OS-41` repo nội bộ. Sửa tự động rủi ro cao
  hơn lợi ích (repartition, đổi UID, chown hàng loạt, nâng cấp gói) nên tool liệt kê
  đầy đủ kèm bằng chứng để người vận hành xử lý.
- **7 mục đánh giá thủ công** — `VIRT-01`, `VIRT-02` (ảo hoá), `OS-19` license,
  `OS-37` SIRC/SIEM, `OS-40` agent giám sát, `OS-43` AAM, `OS-44` thiết kế lưu trữ.
  Nằm ngoài phạm vi OS (do NOC-SOC hoặc theo hồ sơ thiết kế). Tool vẫn dò dấu hiệu
  hỗ trợ đánh giá, và cho **tick tay** ngay trên bảng kết quả — nên report vẫn đủ
  47 mục như file nghiệm thu.

Một số mục tự đánh **N/A** theo ngữ cảnh: bonding/multipath/LLDPD trên máy ảo,
NetworkManager trên Ubuntu (đúng ghi chú *"Linux 7: Không xét"*).

## Tuỳ biến checklist

Sửa `catalog/checklist.json`, thêm hàm check vào `ansible/files/audit_agent.py`
(đăng ký trong danh sách `CHECKS`), và nếu khắc phục tự động được thì thêm block có
`tags: ["OS-xx"]` trong `ansible/roles/harden/tasks/`. Sau đó:

```bash
python3 tests/check_consistency.py
```

Script này chặn tình trạng lệch giữa catalog, agent và tag Ansible.

## API

| Endpoint | Mô tả |
|---|---|
| `POST /api/discovery` | Dò tìm host theo dải IP (chạy nền, trả `scan_id`) |
| `POST /api/scans` | Chạy `audit` hoặc `remediate`; trả **423** nếu credential chưa nhập mật khẩu |
| `POST /api/credentials/{id}/unlock` | Nạp mật khẩu vào RAM cho phiên hiện tại |
| `GET /api/scans/{id}/stream` | Log realtime (SSE) |
| `GET /api/scans/{id}/report.csv\|.html\|.json` | Xuất report |
| `GET /api/compare?before=&after=` | So sánh hai lần chạy |
