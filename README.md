# 🔐 Security Audit Automation

Linux 서버 환경(Ubuntu, Rocky Linux)을 대상으로  
**보안 취약점 점검 → 결과 정규화 → 통계 및 준수율 산출**까지 자동화한 보안 진단 도구입니다.

---

## 📌 1. 개요 (Overview)

본 프로젝트는  
**2026 주요정보통신기반시설 기술적 취약점 분석·평가방법 상세가이드**를 기준으로  
Linux 서버 환경(Ubuntu, Rocky Linux)의 보안 설정 취약점을 자동 점검하고,  
진단 결과를 **분석 및 보고가 가능한 표준 형태(CSV / Excel)**로 변환하기 위해 개발되었습니다.

운영 환경에서 반복적으로 수행되던 수동 보안 점검 작업을 자동화하여  
진단 소요 시간을 단축하고, 결과의 **정합성·일관성·재사용성**을 높이는 것을 목표로 합니다.

---

## 🧭 2. 개발 배경 (Background)

다수의 Linux 서버를 운영·진단하는 환경에서 다음과 같은 문제를 반복적으로 경험했습니다.

- OS별로 상이한 보안 점검 항목과 스크립트 관리 부담
- 진단 결과가 텍스트 파일로만 산출되어 결과 취합 및 요약이 어려움
- 동일 점검 항목이 결과 파일 내 여러 번 등장하여 분석 오류 발생
- 인프라 환경 변화에 따라 스크립트를 지속적으로 수정해야 하는 구조적 한계

이러한 문제를 해결하기 위해  
본 도구는 **OS별 점검 로직과 결과 분석/정규화 로직을 분리**하는 구조로 설계되었습니다.

---

## 🖥️ 3. 지원 환경 (Supported Environments)

- **Ubuntu Linux**
- **Rocky Linux**
- CentOS 계열 OS와 호환 가능한 점검 로직 포함

---

## 🧩 4. 아키텍처 개요 (Architecture)

> **[Target Server]**  
> └─ OS별 보안 점검 스크립트 실행  
> ↓  
> **[Raw Audit Result (.txt)]**  
> ↓  
> **[Parser / Normalizer (Python)]**  
> ↓  
> **[정형화된 결과물 (CSV / Excel)]**

- 점검 수행과 결과 분석을 분리하여 유지보수성과 확장성을 확보했습니다.

---

## ✨ 5. 주요 기능 (Key Features)

- Linux OS별 보안 취약점 자동 점검
  - Ubuntu
  - Rocky Linux
- 점검 결과 텍스트 파일 자동 생성
- 진단 결과 파싱 및 표준 포맷(CSV / Excel) 변환
- 중복 점검 항목 병합 및 결과 정규화
- 파일명 기반 호스트 정보(IP / Hostname / OS) 자동 추출
- 항목별 **취약 / 양호 / 수동확인** 통계 산출
- 서버(IP) 단위 **보안 준수율(%) 자동 계산**

---

## 📁 6. 파일 구성 (File Structure)

```text
.
├── ubuntu_audit.sh        # Ubuntu 보안 취약점 점검 스크립트
├── rocky_audit.sh         # Rocky Linux 보안 취약점 점검 스크립트
├── statistics.py          # 진단 결과 파싱 및 통계/준수율 산출
└── README.md

## ▶️ 7. 사용 방법 (Usage)

### 1️⃣ 대상 서버에서 보안 점검 수행

```bash
bash ubuntu_audit.sh
# 또는
bash rocky_audit.sh
2️⃣ 로컬 환경에서 결과 분석 및 통계 생성
bash
코드 복사
python statistics.py
📊 8. 결과물 (Output)
Raw 진단 결과 텍스트 파일 (.txt)

통합 Excel 보고서 (.xlsx)

Raw 진단 데이터 시트

항목별 취약 / 양호 / 수동확인 집계 시트

서버(IP)별 보안 준수율(%) 시트

⚠️ 9. 한계 및 향후 개선 사항 (Limitations & Future Work)
현재 Ubuntu / Rocky Linux 환경 중심으로 구현

위험도 분류는 점검 결과 상태 기준으로 산출

향후 개선 계획
추가 Linux 배포판 지원

결과 시각화(차트 / 대시보드)

CI/CD 기반 자동 점검 연계

🧠 참고
본 프로젝트는
실제 운영 환경에서 반복 수행되던 보안 취약점 점검 업무를 자동화하기 위해 설계되었으며,
보안 컨설팅, 내부 점검, ISMS 및 주요정보통신기반시설 대응 환경을 고려하여 구현되었습니다.
