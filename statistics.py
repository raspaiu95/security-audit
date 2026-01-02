import os
import re
import pandas as pd

# =========================
# 설정
# =========================
INPUT_DIR = "C:\Users\username\Desktop\.."
OUTPUT_FILE = "security_audit_result.xlsx"
TOTAL_ITEMS = 67

# =========================
# 정규식
# =========================
DATE_PATTERN = re.compile(r"점검 일시:\s*(.+)")
ITEM_PATTERN = re.compile(r"\[(U-\d+)\]\s*(.+)")
RESULT_PATTERN = re.compile(r"- 결과:\s*(.+)")
REASON_PATTERN = re.compile(r"- 근거:\s*(.+)")

FILENAME_PATTERN = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)@@.+?@@(?P<os>Ubuntu|Rocky)_(?P<version>[\d.]+)",
    re.IGNORECASE
)

rows = []

# =========================
# TXT 파싱
# =========================
for file_name in os.listdir(INPUT_DIR):
    if not file_name.lower().endswith(".txt"):
        continue

    m = FILENAME_PATTERN.search(file_name)
    if not m:
        continue

    ip_addr = m.group("ip")
    os_info = f"{m.group('os')} {m.group('version')}"

    with open(os.path.join(INPUT_DIR, file_name), encoding="utf-8") as f:
        lines = f.readlines()

    check_date = ""
    item_id = item_name = result = reason = ""

    for line in lines:
        line = line.strip()

        if not check_date:
            m = DATE_PATTERN.search(line)
            if m:
                check_date = m.group(1)

        m = ITEM_PATTERN.search(line)
        if m:
            item_id, item_name = m.group(1), m.group(2)
            continue

        m = RESULT_PATTERN.search(line)
        if m:
            result = m.group(1)
            continue

        m = REASON_PATTERN.search(line)
        if m:
            reason = m.group(1)

            rows.append({
                "점검일시": check_date,
                "OS": os_info,
                "IP": ip_addr,
                "항목ID": item_id,
                "점검항목": item_name,
                "결과": result,
                "근거": reason
            })

# =========================
# Raw Data
# =========================
df_raw = pd.DataFrame(rows)

# =========================
# 항목별 결과 집계
# =========================
item_summary = (
    df_raw
    .pivot_table(
        index=["항목ID", "점검항목"],
        columns="결과",
        values="IP",
        aggfunc="count",
        fill_value=0
    )
    .reset_index()
)

item_summary["전체"] = item_summary[["양호", "취약", "수동확인"]].sum(axis=1)

# =========================
# 서버별 준수율
# =========================
server_summary = (
    df_raw
    .pivot_table(
        index=["IP", "OS"],
        columns="결과",
        values="항목ID",
        aggfunc="count",
        fill_value=0
    )
    .reset_index()
)

server_summary["전체항목"] = TOTAL_ITEMS
server_summary["준수율(%)"] = round((server_summary.get("양호", 0) / TOTAL_ITEMS) * 100, 2)

# =========================
# 엑셀 출력
# =========================
with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as writer:
    df_raw.to_excel(writer, sheet_name="RawData", index=False)
    item_summary.to_excel(writer, sheet_name="항목별_결과집계", index=False)
    server_summary.to_excel(writer, sheet_name="서버별_준수율", index=False)

print(f"[완료] 엑셀 생성: {OUTPUT_FILE}")