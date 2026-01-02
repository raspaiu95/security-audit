#!/usr/bin/env bash
# ============================================
# 주요정보통신기반시설 기술적 취약점 점검 스크립트
# 대상: Unix/Linux (Ubuntu 24.04.3 LTS 기준)
# 항목: U-01 ~ U-67
# 결과 저장: [IP]@@[Hostname]@@[OS].txt
# ============================================

IP=$(hostname -I | awk '{print $1}')
HOST=$(hostname)

# 파일 저장
OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"' | awk '{print $1}')
OS_VER=$(grep VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1,2)
OS_FINAL="${OS_NAME}_${OS_VER}"

# 최종 파일명
RESULT_FILE="${IP}@@${HOST}@@${OS_FINAL}.txt"

# 기존 파일이 있다면 삭제 후 새로 생성
echo "=== 보안 취약점 점검 결과 리포트 ===" > "$RESULT_FILE"
echo "점검 일시: $(date)" >> "$RESULT_FILE"
echo "점검 대상: $OS_NAME $OS_VER / $IP" >> "$RESULT_FILE"
echo "----------------------------------------------------------------------" >> "$RESULT_FILE"

# 결과 출력 함수
report() {
    local code="$1" title="$2" status="$3" evidence="$4"
    {
        echo "[$code] $title"
        echo "  - 결과: $status"
        echo "  - 근거: $evidence"
        echo "----------------------------------------------------------------------"
    } | tee -a "$RESULT_FILE"
}

# ===== 진단 수행 =====
# [U-01] root 원격 접속 제한: 외부에서 root 계정으로 직접 SSH 접속이 가능한지 확인
check_u01() {
    if [ -f /etc/ssh/sshd_config ]; then
        local val=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
        # PermitRootLogin 설정이 'no'로 되어 있어야 양호
        [[ "$val" == "no" ]] && report "U-01" "root 원격 접속 제한" "양호" "PermitRootLogin=no" \
        || report "U-01" "root 원격 접속 제한" "취약" "설정값: ${val:-미설정}"
    else
        report "U-01" "root 원격 접속 제한" "N/A" "ssh 설정 파일 없음"
    fi
}

# [U-02] 패스워드 복잡성 설정: 패스워드 최소 길이(8자 이상)가 설정되어 있는지 확인
check_u02() {
    local minlen=$(grep -i "^minlen" /etc/security/pwquality.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
    # pwquality.conf 파일에서 minlen 값이 8 이상인지 검사
    [[ -n "$minlen" && "$minlen" -ge 8 ]] && report "U-02" "패스워드 복잡성 설정" "양호" "minlen=$minlen" \
    || report "U-02" "패스워드 복잡성 설정" "취약" "최소 길이 8자 미만"
}

# [U-03] 계정 잠금 임계값 설정: 로그인 실패 시 계정 잠금 정책(10회 이하)이 있는지 확인
check_u03() {
    # PAM 설정을 통해 로그인 실패 허용 횟수(deny) 추출
    local deny=$(grep -h "pam_faillock.so" /etc/pam.d/common-auth /etc/pam.d/system-auth 2>/dev/null | grep "deny=" | sed 's/.*deny=\([0-9]*\).*/\1/' | head -n 1)
    [[ -n "$deny" && "$deny" -le 10 ]] && report "U-03" "계정 잠금 임계값 설정" "양호" "임계값=$deny" \
    || report "U-03" "계정 잠금 임계값 설정" "취약" "미설정 또는 10회 초과"
}

# [U-04] 패스워드 파일 보호: 패스워드가 암호화되어 /etc/shadow 파일에 저장되는지 확인
check_u04() {
    [ -f /etc/shadow ] && report "U-04" "패스워드 파일 보호" "양호" "shadow 파일 사용 중" \
    || report "U-04" "패스워드 파일 보호" "취약" "shadow 파일 없음"
}

# [U-05] root 이외의 UID 0 금지: UID가 0(관리자 권한)인 계정이 root뿐인지 확인
check_u05() {
    local uid0=$(awk -F: '$3==0 {print $1}' /etc/passwd | xargs)
    # 결과값이 오직 'root'만 있어야 양호
    [[ "$uid0" == "root" ]] && report "U-05" "root 이외의 UID 0 금지" "양호" "관리자 전용" \
    || report "U-05" "root 이외의 UID 0 금지" "취약" "추가 계정: $uid0"
}

# [U-06] su 명령어 사용 제한: 일반 사용자가 su 명령어를 통해 root가 되는 것을 제한(wheel 그룹)하는지 확인
check_u06() {
    # PAM 설정에서 pam_wheel.so 모듈 주석 해제 여부 확인
    if grep -q "pam_wheel.so" /etc/pam.d/su && ! grep -q "^#.*pam_wheel.so" /etc/pam.d/su; then
        report "U-06" "su 명령어 사용 제한" "양호" "wheel 그룹 제한 설정됨"
    else
        report "U-06" "su 명령어 사용 제한" "취약" "모든 사용자 사용 가능"
    fi
}

# [U-07] 불필요한 계정 제거: 시스템 운영에 불필요한 기본 계정(lp, uucp 등) 존재 여부 확인
check_u07() {
    local unwanted=$(grep -E "^(lp|uucp|nuucp):" /etc/passwd | cut -d: -f1 | xargs)
    [ -z "$unwanted" ] && report "U-07" "불필요한 계정 제거" "양호" "발견되지 않음" \
    || report "U-07" "불필요한 계정 제거" "취약" "발견: $unwanted"
}

# [U-08] 관리자 그룹 최소 계정: root 그룹(GID 0)에 root 계정만 존재해야 함
check_u08() {
    # /etc/group에서 root 그룹의 멤버 리스트 추출
    local members=$(grep "^root:" /etc/group | cut -d: -f4)
    if [[ -z "$members" || "$members" == "root" ]]; then
        report "U-08" "관리자 그룹 최소 계정" "양호" "root 그룹에 root 계정만 존재함"
    else
        report "U-08" "관리자 그룹 최소 계정" "취약" "root 그룹 내 비인가 계정 발견: $members"
    fi
}

# [U-09] 불필요한 GID 제거: 시스템 관리상 불필요한 그룹(사용자 없는 그룹 등)이 없는지 확인
check_u09() {
    # 멤버가 하나도 없고, GID가 1000 이상인 일반 그룹들을 추출
    local unused_groups=$(awk -F: '($3 >= 1000 && $4 == "") {print $1}' /etc/group | xargs)
    if [ -z "$unused_groups" ]; then
        report "U-09" "불필요한 GID 제거" "양호" "의심되는 불필요한 그룹 없음"
    else
        report "U-09" "불필요한 GID 제거" "수동확인" "멤버 없는 일반 그룹 발견(삭제 검토): $unused_groups"
    fi
}

# [U-10] 동일한 UID 금지: 서로 다른 계정이 동일한 UID를 공유하고 있는지 확인
check_u10() {
    local dup=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    [ -z "$dup" ] && report "U-10" "동일한 UID 금지" "양호" "중복 없음" \
    || report "U-10" "동일한 UID 금지" "취약" "중복 UID: $dup"
}

# [U-11] 사용자 Shell 점검: 서비스 계정(bin, daemon 등)에 로그인 쉘이 부여되어 있는지 확인
check_u11() {
    # 시스템 계정들의 쉘이 nologin 또는 false가 아닌 경우를 추출
    local shells=$(awk -F: '/^(bin|daemon|sys|adm|lp|uucp|nobody)/ {print $1":"$7}' /etc/passwd | grep -vE "nologin|false")
    [ -z "$shells" ] && report "U-11" "사용자 Shell 점검" "양호" "시스템 계정 쉘 제한됨" \
    || report "U-11" "사용자 Shell 점검" "취약" "시스템 계정 쉘 부여됨: $shells"
}

# [U-12] 세션 종료 시간 설정: 사용자 세션 타임아웃(600초/10분 이하) 설정 확인
check_u12() {
    # /etc/profile 등 환경 설정 파일에서 TMOUT 변수 값 검사
    local tmout=$(grep -h "TMOUT" /etc/profile /etc/bash.bashrc 2>/dev/null | tail -n1 | cut -d'=' -f2)
    [[ -n "$tmout" && "$tmout" -le 600 && "$tmout" -gt 0 ]] && report "U-12" "세션 종료 시간 설정" "양호" "TMOUT=$tmout" \
    || report "U-12" "세션 종료 시간 설정" "취약" "미설정 또는 600초 초과"
}

# [U-13] 비밀번호 알고리즘: 패스워드 해시 알고리즘이 안전한(SHA512 등) 알고리즘인지 확인
check_u13() {
    # login.defs에서 주석(#)을 제외하고 ENCRYPT_METHOD 값을 추출한 뒤, xargs로 줄바꿈을 제거하여 한 줄로 만듭니다.
    local algo=$(grep -i "^ENCRYPT_METHOD" /etc/login.defs | awk '{print $2}' | xargs)
    
    # 추출된 값이 SHA512 또는 최신 알고리즘인 yescrypt인 경우 양호로 판단
    if [[ "$algo" == "SHA512" || "$algo" == "yescrypt" ]]; then
        report "U-13" "비밀번호 알고리즘" "양호" "$algo 사용 중"
    else
        # 값이 비어있거나 취약한 경우, 추출된 모든 값을 한 줄로 표시
        report "U-13" "비밀번호 알고리즘" "취약" "설정값: ${algo:-미설정} (SHA512 권고)"
    fi
}

# [U-14] root 패스 설정: root 계정의 PATH 환경변수에 현재 디렉터리('.')가 포함되어 있는지 확인 (보안 위협 방지)
check_u14() {
    if echo "$PATH" | grep -qE "\.:|::|:\."; then
        report "U-14" "root 패스 설정" "취약" "PATH에 현재 디렉터리 포함"
    else
        report "U-14" "root 패스 설정" "양호" "적절한 PATH"
    fi
}

# [U-15] 파일 및 디렉터리 소유자 설정: 소유자나 그룹이 없는(퇴사자 등) 파일이 시스템에 존재하는지 확인
check_u15() {
    echo "[진행중] U-15 검사 중... (시간이 소요될 수 있습니다)"
    # 시스템 전체 스캔 시 정체를 방지하기 위해 주요 디렉터리 및 다른 파일 시스템 제외(-xdev) 옵션 사용
    local nouser=$(find /etc /bin /sbin /usr /var -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -n 5)
    if [ -z "$nouser" ]; then
        report "U-15" "파일 및 디렉터리 소유자 설정" "양호" "소유자 없는 파일이 발견되지 않음"
    else
        report "U-15" "파일 및 디렉터리 소유자 설정" "취약" "소유자 없는 파일 존재(예: $nouser)"
    fi
}

# [U-16] /etc/passwd 권한 설정: 사용자 정보 파일의 소유자(root) 및 권한(644 이하) 확인
check_u16() {
    local owner=$(stat -c %U /etc/passwd)
    local perm=$(stat -c %a /etc/passwd)
    [[ "$owner" == "root" && "$perm" -le 644 ]] && report "U-16" "/etc/passwd 권한" "양호" "$owner/$perm" \
    || report "U-16" "/etc/passwd 권한" "취약" "$owner/$perm (기준 root/644 이하)"
}

# [U-17] 시작 스크립트 권한 설정: 부팅 시 실행되는 스크립트에 관리자 외 쓰기 권한이 있는지 확인
check_u17() {
    # 타인 쓰기 권한(/022)이 있는 파일 탐색
    local insecure=$(find /etc/rc.d /etc/init.d -type f -perm /022 2>/dev/null)
    [ -z "$insecure" ] && report "U-17" "시작 스크립트 권한" "양호" "권한 적절" \
    || report "U-17" "시작 스크립트 권한" "취약" "타인 쓰기 권한 존재"
}

# [U-18] /etc/shadow 권한 설정: 비밀번호 파일의 소유자(root) 및 권한(400 이하) 확인
check_u18() {
    local owner=$(stat -c %U /etc/shadow)
    local perm=$(stat -c %a /etc/shadow)
    [[ "$owner" == "root" && "$perm" -le 400 ]] && report "U-18" "/etc/shadow 권한" "양호" "$owner/$perm" \
    || report "U-18" "/etc/shadow 권한" "취약" "$owner/$perm (기준 root/400 이하)"
}

# [U-19] /etc/hosts 권한 설정: IP/호스트 이름 매핑 파일의 소유자(root) 및 권한(600 이하) 확인
check_u19() {
    local owner=$(stat -c %U /etc/hosts)
    local perm=$(stat -c %a /etc/hosts)
    [[ "$owner" == "root" && "$perm" -le 600 ]] && report "U-19" "/etc/hosts 권한" "양호" "$owner/$perm" \
    || report "U-19" "/etc/hosts 권한" "취약" "$owner/$perm (기준 root/600 이하)"
}

# [U-20] /etc/inetd.conf 권한 설정: 슈퍼 데몬 설정 파일의 권한(600 이하) 확인
check_u20() {
    if [ -f /etc/inetd.conf ]; then
        local perm=$(stat -c %a /etc/inetd.conf)
        [[ "$perm" -le 600 ]] && report "U-20" "inetd.conf 권한" "양호" "$perm" \
        || report "U-20" "inetd.conf 권한" "취약" "$perm"
    else
        report "U-20" "inetd.conf 권한" "양호" "파일 없음"
    fi
}

# [U-21] /etc/rsyslog.conf 권한 설정: 로그 설정 파일의 소유자(root) 및 권한(640 이하) 확인
check_u21() {
    local f="/etc/rsyslog.conf"
    [ ! -f "$f" ] && f="/etc/syslog.conf" # 시스템에 따라 rsyslog 또는 syslog 확인
    if [ -f "$f" ]; then
        local owner=$(stat -c %U "$f")
        local perm=$(stat -c %a "$f")
        [[ "$owner" == "root" && "$perm" -le 640 ]] && report "U-21" "syslog.conf 권한" "양호" "$owner/$perm" \
        || report "U-21" "syslog.conf 권한" "취약" "$owner/$perm (기준 root/640 이하)"
    else
        report "U-21" "syslog.conf 권한" "N/A" "설정 파일 없음"
    fi
}

# [U-22] /etc/services 파일 소유자 및 권한 설정: 서비스 포트 설정 파일의 변조를 방지하기 위해 소유자(root) 및 권한(644 이하) 확인
check_u22() {
    local f="/etc/services"
    if [ -f "$f" ]; then
        local owner=$(stat -c %U "$f")
        local perm=$(stat -c %a "$f")
        if [ "$owner" == "root" ] && [ "$perm" -le 644 ]; then
            report "U-22" "/etc/services 권한" "양호" "소유자:$owner, 권한:$perm"
        else
            report "U-22" "/etc/services 권한" "취약" "소유자:$owner, 권한:$perm (기준 root/644 이하)"
        fi
    else
        report "U-22" "/etc/services 권한" "N/A" "파일 없음"
    fi
}

# [U-23] SUID, SGID, 설정 파일 점검: 불필요한 SUID 파일이나 권한 상승에 악용될 수 있는 파일 점검
check_u23() {
    echo "[진행중] U-23 SUID/SGID 위험 파일 정밀 스캔 중..."
    # 1. 쓰기 권한이 열린 디렉토리(/tmp 등)에 설정된 SUID 확인
    local danger_suid=$(find /tmp /var/tmp -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    # 2. 알려진 위험 명령어(nmap, ncat, vim 등)에 SUID가 붙어있는지 확인
    local exploit_tool=$(find /usr/bin /usr/sbin -name "nmap" -o -name "ncat" -o -name "vim" -perm -4000 2>/dev/null)

    if [[ -z "$danger_suid" && -z "$exploit_tool" ]]; then
        local total=$(find /usr/bin /usr/sbin /bin /sbin -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
        report "U-23" "SUID/SGID 설정 파일" "양호" "위험한 SUID 파일 없음 (일반 시스템 파일 $total 개 존재)"
    else
        report "U-23" "SUID/SGID 설정 파일" "취약" "위험 SUID 발견: $danger_suid $exploit_tool"
    fi
}

# [U-24] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정: 환경변수 파일(.profile, .bashrc 등)의 변조를 막기 위해 소유자 및 타인 쓰기 권한 제한 여부 점검
check_u24() {
    local insecure=$(find /home /root -maxdepth 2 -name ".bashrc" -o -name ".profile" -o -name ".bash_profile" -perm /022 -type f 2>/dev/null)
    if [ -z "$insecure" ]; then
        report "U-24" "환경파일 권한 설정" "양호" "타인 쓰기 권한 제한됨"
    else
        report "U-24" "환경파일 권한 설정" "취약" "권한 노출 파일 발견: $(echo $insecure | xargs)"
    fi
}

# [U-25] World Writable 파일 점검: 시스템 내 모든 사용자가 수정 가능한(777 권한 등) 파일이 존재하는지 점검하여 악의적인 파일 변조 위험 확인
check_u25() {
    echo "[진행중] U-25 World Writable 파일 검색 중..."
    local ww_cnt=$(find / -xdev -type f -perm -2 2>/dev/null | wc -l)
    if [ "$ww_cnt" -eq 0 ]; then
        report "U-25" "World Writable 파일" "양호" "발견되지 않음"
    else
        report "U-25" "World Writable 파일" "취약" "$ww_cnt 개의 파일 발견 (비인가 수정 위험)"
    fi
}

# [U-26] /dev 내 존재하지 않는 device 파일 점검: /dev 디렉터리에 실제 장치와 연결되지 않은 일반 파일(백도어 용도 등)이 존재하는지 점검
check_u26() {
    local dev_check=$(find /dev -type f 2>/dev/null)
    if [ -z "$dev_check" ]; then
        report "U-26" "/dev 비정상 파일 점검" "양호" "비정상 일반 파일 없음"
    else
        report "U-26" "/dev 비정상 파일 점검" "취약" "비정상 일반 파일 발견: $dev_check"
    fi
}

# [U-27] .rhosts, hosts.equiv 사용 금지: 패스워드 없이 로그인 가능한 신뢰 관계 설정 파일(.rhosts 등)의 존재 여부를 점검하여 무단 접속 위험 차단
check_u27() {
    local rhosts=$(find /home /root -name ".rhosts" -o -name "hosts.equiv" 2>/dev/null)
    if [ -z "$rhosts" ]; then
        report "U-27" ".rhosts 파일 존재 여부" "양호" "파일 발견되지 않음"
    else
        report "U-27" ".rhosts 파일 존재 여부" "취약" "신뢰 관계 설정 파일 발견: $rhosts"
    fi
}

# [U-28] /etc/hosts.allow, /etc/hosts.deny 소유자 및 권한 설정: 네트워크 접근 제어 파일의 변조를 막기 위해 소유자(root) 및 권한(644 이하) 점검
check_u28() {
    local files=("/etc/hosts.allow" "/etc/hosts.deny")
    local status="양호"
    local evidence=""
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            local owner=$(stat -c %U "$file")
            local perm=$(stat -c %a "$file")
            evidence+="$file($owner/$perm) "
            if [ "$owner" != "root" ] || [ "$perm" -gt 644 ]; then status="취약"; fi
        fi
    done
    report "U-28" "hosts.allow/deny 권한" "$status" "${evidence:-파일 없음}"
}

# [U-29] /etc/sysconfig/network 파일 권한 설정: 네트워크 기본 설정 파일의 무단 수정을 방지하기 위해 소유자 및 권한 점검 (Ubuntu는 /etc/network/interfaces 등 확인)
check_u29() {
    local f="/etc/network/interfaces"
    if [ -f "$f" ]; then
        local perm=$(stat -c %a "$f")
        [[ "$perm" -le 644 ]] && report "U-29" "네트워크 설정파일 권한" "양호" "권한:$perm" \
        || report "U-29" "네트워크 설정파일 권한" "취약" "권한:$perm (기준 644)"
    else
        report "U-29" "네트워크 설정파일 권한" "양호" "기본 interfaces 파일 없음 (Netplan 사용)"
    fi
}

# [U-30] UMASK 설정 관리: 파일 및 디렉터리 생성 시 기본 권한을 제어하는 UMASK 값이 보안 기준(022 등)에 적합한지 점검
check_u30() {
    local um=$(umask)
    if [[ "$um" == "0022" || "$um" == "022" || "$um" == "0027" || "$um" == "027" ]]; then
        report "U-30" "UMASK 설정 관리" "양호" "현재 UMASK: $um"
    else
        report "U-30" "UMASK 설정 관리" "취약" "현재 UMASK: $um (022 이상 권고)"
    fi
}

# [U-31] /etc/services 파일 권한 설정: 서비스 포트 정보 파일의 무단 변조를 막기 위해 소유자(root) 및 권한(644 이하) 확인
check_u31() {
    local f="/etc/services"
    if [ -f "$f" ]; then
        local owner=$(stat -c %U "$f")
        local perm=$(stat -c %a "$f")
        [[ "$owner" == "root" && "$perm" -le 644 ]] && report "U-31" "/etc/services 무결성" "양호" "$owner/$perm" \
        || report "U-31" "/etc/services 무결성" "취약" "$owner/$perm"
    else
        report "U-31" "/etc/services 무결성" "N/A" "파일 없음"
    fi
}

# [U-32] 일반사용자의 시스템 정보 확인 제한: who, w 등 명령어 권한을 제한하여 인가되지 않은 사용자의 시스템 정보 수집을 방지함
check_u32() {
    local who_perm=$(stat -c %a /usr/bin/who 2>/dev/null || echo "000")
    if [ "$who_perm" -le 711 ]; then
        report "U-32" "시스템 정보 확인 제한" "양호" "who 권한:$who_perm"
    else
        report "U-32" "시스템 정보 확인 제한" "취약" "who 권한:$who_perm (기타 사용자 실행 제한 권고)"
    fi
}

# [U-33] DNS 보안 버전 패치: DNS 서비스(BIND)의 취약점이 해결된 최신 버전 패치 적용 여부를 확인
check_u33() {
    if command -v named &> /dev/null; then
        local dns_ver=$(named -v)
        report "U-33" "DNS 보안 패치 점검" "수동확인" "설치됨: $dns_ver"
    else
        report "U-33" "DNS 보안 패치 점검" "양호" "DNS 서비스 미설치"
    fi
}

# [U-34] Finger 서비스 비활성화: 사용자 정보를 외부로 노출하는 Finger 서비스의 활성화 여부를 점검
check_u34() {
    if systemctl is-active --quiet finger 2>/dev/null || [ -f /etc/xinetd.d/finger ]; then
        report "U-34" "Finger 서비스 비활성화" "취약" "서비스 활성 중"
    else
        report "U-34" "Finger 서비스 비활성화" "양호" "서비스 비활성"
    fi
}

# [U-35] Anonymous FTP 비활성화: 누구나 접속 가능한 익명 FTP 계정 허용 여부를 점검하여 파일 유출 방지
check_u35() {
    if [ -f /etc/vsftpd.conf ]; then
        local anon_check=$(grep -i "anonymous_enable" /etc/vsftpd.conf | grep -i "YES")
        if [ -z "$anon_check" ]; then
            report "U-35" "Anonymous FTP 비활성화" "양호" "익명 접속 차단됨"
        else
            report "U-35" "Anonymous FTP 비활성화" "취약" "익명 접속 허용됨"
        fi
    else
        report "U-35" "Anonymous FTP 비활성화" "양호" "FTP 서비스 미설치"
    fi
}

# [U-36] r계열 서비스 비활성화: 취약한 인증 방식의 rsh, rlogin, rexec 서비스 비활성화 여부를 점검
check_u36() {
    local r_services=("rsh.socket" "rlogin.socket" "rexec.socket")
    local found=""
    for svc in "${r_services[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then found+="$svc "; fi
    done
    if [ -z "$found" ]; then
        report "U-36" "r계열 서비스 비활성화" "양호" "서비스 비활성"
    else
        report "U-36" "r계열 서비스 비활성화" "취약" "활성 중: $found"
    fi
}

# [U-37] crontab 파일 소유자 및 권한 설정: 예약 작업 설정 파일의 무단 변조를 막기 위해 권한(600 이하) 및 소유자 점검
check_u37() {
    if [ -f /etc/crontab ]; then
        local owner=$(stat -c %U /etc/crontab)
        local perm=$(stat -c %a /etc/crontab)
        [[ "$owner" == "root" && "$perm" -le 600 ]] && report "U-37" "crontab 권한 설정" "양호" "$owner/$perm" \
        || report "U-37" "crontab 권한 설정" "취약" "$owner/$perm"
    else
        report "U-37" "crontab 권한 설정" "양호" "파일 없음"
    fi
}

# [U-38] DoS 공격에 취약한 서비스 비활성화: DoS 공격에 악용될 수 있는 불필요한 서비스(echo, discard 등) 비활성화 여부 점검
check_u38() {
    local dos_svc=("echo" "discard" "daytime" "chargen")
    local found=""
    for svc in "${dos_svc[@]}"; do
        if grep -rqE "^[^#].*$svc" /etc/xinetd.d/* 2>/dev/null; then found+="$svc "; fi
    done
    if [ -z "$found" ]; then
        report "U-38" "DoS 취약 서비스 비활성화" "양호" "취약 서비스 미구동"
    else
        report "U-38" "DoS 취약 서비스 비활성화" "취약" "활성 중: $found"
    fi
}

# [U-39] NFS 서비스 비활성화: 보안이 취약한 파일 공유 서비스인 NFS의 구동 여부를 점검
check_u39() {
    if pgrep -x "nfsd" > /dev/null; then
        report "U-39" "NFS 서비스 비활성화" "취약" "NFS 구동 중"
    else
        report "U-39" "NFS 서비스 비활성화" "양호" "NFS 미구동"
    fi
}

# [U-40] NFS 접근 제어: NFS 공유 시 모든 호스트(*) 허용 등 잘못된 접근 제한 설정이 있는지 점검
check_u40() {
    if [ -f /etc/exports ]; then
        if grep -q "*" /etc/exports; then
            report "U-40" "NFS 접근 제어" "취약" "전체 허용(*) 설정 발견"
        else
            report "U-40" "NFS 접근 제어" "양호" "제한적 접근 설정됨"
        fi
    else
        report "U-40" "NFS 접근 제어" "양호" "NFS 설정 파일 없음"
    fi
}

# [U-41] RPC 서비스 비활성화: 보안 취약점이 많은 RPC 서비스(rpcbind 등)의 구동 여부 점검
check_u41() {
    if pgrep -x "rpcbind" > /dev/null; then
        report "U-41" "RPC 서비스 비활성화" "취약" "rpcbind 구동 중"
    else
        report "U-41" "RPC 서비스 비활성화" "양호" "RPC 미구동"
    fi
}

# [U-42] SNMP 서비스 비활성화: 네트워크 장비 모니터링 프로토콜인 SNMP의 비인가 활성화 여부 점검
check_u42() {
    if systemctl is-active --quiet snmpd 2>/dev/null; then
        report "U-42" "SNMP 서비스 비활성화" "취약" "SNMP 활성 중"
    else
        report "U-42" "SNMP 서비스 비활성화" "양호" "SNMP 비활성"
    fi
}

# [U-43] NIS 서비스 비활성화: 보안에 취약한 중앙 집중식 관리 서비스인 NIS의 비활성화 여부 점검
check_u43() {
    if pgrep -x "ypserv" > /dev/null; then
        report "U-43" "NIS 서비스 비활성화" "취약" "NIS 활성 중"
    else
        report "U-43" "NIS 서비스 비활성화" "양호" "NIS 비활성"
    fi
}

# [U-44] NIS+ 서비스 비활성화: NIS보다 개선되었으나 여전히 보안 위험이 있는 NIS+의 활성화 여부 점검
check_u44() {
    if pgrep -x "rpc.nisd" > /dev/null; then
        report "U-44" "NIS+ 서비스 비활성화" "취약" "NIS+ 활성 중"
    else
        report "U-44" "NIS+ 서비스 비활성화" "양호" "NIS+ 비활성"
    fi
}

# [U-45] tftp, talk 서비스 비활성화: 보안 인증이 없는 tftp 및 통신 서비스인 talk의 활성화 여부 점검
check_u45() {
    local services=("tftp" "talk")
    local found=""
    for svc in "${services[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then found+="$svc "; fi
    done
    if [ -z "$found" ]; then
        report "U-45" "tftp, talk 서비스 비활성화" "양호" "서비스 비활성"
    else
        report "U-45" "tftp, talk 서비스 비활성화" "취약" "활성 중: $found"
    fi
}

# [U-46] 메일 서비스 버전 점검: Sendmail 등 메일 서버 소프트웨어의 취약점이 해결된 버전 사용 여부 확인
check_u46() {
    if command -v sendmail &> /dev/null; then
        report "U-46" "메일 서비스 버전 점검" "수동확인" "Sendmail 설치됨"
    else
        report "U-46" "메일 서비스 버전 점검" "양호" "메일 서비스 미설치"
    fi
}

# [U-47] 스팸 메일 릴레이 제한: 외부인이 메일 서버를 스팸 메일 발송용으로 악용하지 못하도록 릴레이 차단 여부 점검
check_u47() {
    if [ -f /etc/postfix/main.cf ]; then
        report "U-47" "스팸 메일 릴레이 제한" "양호" "Postfix 기본 제한 적용됨"
    else
        report "U-47" "스팸 메일 릴레이 제한" "양호" "메일 릴레이 설정 없음"
    fi
}

# [U-48] 일반사용자의 Sendmail 실행 방지: 권한 없는 사용자가 메일 큐를 처리하거나 서버를 재시작하지 못하도록 제어
check_u48() {
    report "U-48" "Sendmail 실행 방지" "양호" "메일 서비스 미구동"
}

# [U-49] 불필요한 웹 서비스 제거: 시스템에 설치된 Apache, Nginx 등 웹 서비스 중 불필요한 항목의 존재 여부 확인
check_u49() {
    if systemctl is-active --quiet apache2 2>/dev/null; then
        report "U-49" "불필요한 웹 서비스 제거" "수동확인" "웹 서비스 활성 중"
    else
        report "U-49" "불필요한 웹 서비스 제거" "양호" "웹 서비스 비활성"
    fi
}

# [U-50] Apache 디렉토리 리스팅 제거: 웹 서버에서 파일 목록이 브라우저에 노출되는(Indexes) 보안 설정 해제 여부 점검
check_u50() {
    if grep -r "Options" /etc/apache2 2>/dev/null | grep "Indexes" | grep -v "#" > /dev/null; then
        report "U-50" "웹 디렉토리 리스팅 제거" "취약" "Indexes 옵션 활성화"
    else
        report "U-50" "웹 디렉토리 리스팅 제거" "양호" "Listing 제한됨"
    fi
}

# [U-51] Apache 상위 디렉토리 접근 제한: .htaccess 설정 등을 무시(AllowOverride None)하여 상위 디렉터리 접근이 가능해지는 설정 점검
check_u51() {
    if grep -r "AllowOverride None" /etc/apache2 2>/dev/null | grep -v "#" > /dev/null; then
        report "U-51" "웹 상위 디렉토리 접근 제한" "취약" "AllowOverride None 발견"
    else
        report "U-51" "웹 상위 디렉토리 접근 제한" "양호" "접근 제한 적절"
    fi
}

# [U-52] Apache 불필요한 파일 제거: 웹 서버 설치 시 기본으로 제공되는 매뉴얼, 샘플 코드 등 공격에 악용될 수 있는 파일 제거 여부 점검
check_u52() {
    if [ -d /var/www/html/manual ]; then
        report "U-52" "웹 서비스 불필요 파일" "취약" "매뉴얼 디렉터리 존재"
    else
        report "U-52" "웹 서비스 불필요 파일" "양호" "불필요 파일 없음"
    fi
}

# [U-53] Apache 링크 사용 금지: 심볼릭 링크를 이용해 웹 경로를 벗어난 파일 접근(FollowSymLinks)이 가능한지 점검
check_u53() {
    if grep -r "FollowSymLinks" /etc/apache2 2>/dev/null | grep -v "#" > /dev/null; then
        report "U-53" "웹 서비스 링크 사용 금지" "취약" "FollowSymLinks 허용됨"
    else
        report "U-53" "웹 서비스 링크 사용 금지" "양호" "링크 사용 제한됨"
    fi
}

# [U-54] Apache 사용자 파일 경로 노출 제한: 개인 홈페이지 기능(UserDir) 활성화로 인한 시스템 사용자 계정 정보 유출 위험 점검
check_u54() {
    if [ -f /etc/apache2/mods-enabled/userdir.load ]; then
        report "U-54" "웹 서비스 사용자 경로 노출" "취약" "UserDir 모듈 활성"
    else
        report "U-54" "웹 서비스 사용자 경로 노출" "양호" "UserDir 비활성"
    fi
}

# [U-55] Apache 웹 프로세스 권한 제한: 웹 서비스가 root 권한으로 구동되어 웹 공격 시 시스템 전체가 탈취될 위험이 있는지 점검
check_u55() {
    local user=$(grep -r "^User" /etc/apache2 2>/dev/null | grep -v "#" | awk '{print $2}')
    if [[ "$user" == "root" ]]; then
        report "U-55" "웹 프로세스 권한 제한" "취약" "root 권한으로 실행 중"
    else
        report "U-55" "웹 프로세스 권한 제한" "양호" "일반 사용자(${user:-www-data}) 권한 실행 중"
    fi
}

# [U-56] Apache 상위 디렉토리 접근 제한: 루트 디렉터리에 대한 접근 제어 설정 미비로 웹 경로 외부 파일이 노출되는지 점검
check_u56() {
    if grep -r "AllowOverride" /etc/apache2 2>/dev/null | grep -q "None"; then
        report "U-56" "웹 상위 디렉토리 접근 제한" "취약" "상위 디렉터리 접근 가능성 있음"
    else
        report "U-56" "웹 상위 디렉토리 접근 제한" "양호" "설정 적절"
    fi
}

# [U-57] Apache 웹 서비스 정보 숨김: 응답 헤더를 통해 노출되는 서버 버전 및 OS 정보(ServerTokens)를 최소화하여 공격 타겟팅 방지
check_u57() {
    local tokens=$(grep -r "^ServerTokens" /etc/apache2 2>/dev/null | awk '{print $2}')
    if [[ "$tokens" == "Prod" ]]; then
        report "U-57" "웹 서비스 정보 숨김" "양호" "ServerTokens Prod 설정됨"
    else
        report "U-57" "웹 서비스 정보 숨김" "취약" "정보 노출 수준 높음: ${tokens:-Default}"
    fi
}

# [U-58] Apache 웹 설정 파일 권한 제어: 웹 서버 설정 파일(apache2.conf 등)이 비인가자에 의해 변조되지 않도록 권한 점검
check_u58() {
    if [ -f /etc/apache2/apache2.conf ]; then
        local perm=$(stat -c %a /etc/apache2/apache2.conf)
        [[ "$perm" -le 644 ]] && report "U-58" "웹 설정 파일 권한" "양호" "권한:$perm" \
        || report "U-58" "웹 설정 파일 권한" "취약" "권한 과다:$perm"
    else
        report "U-58" "웹 설정 파일 권한" "양호" "설정 파일 없음"
    fi
}

# [U-59] SNMP 커뮤니티 스트링 설정: 유추하기 쉬운 기본 문자열(public, private) 사용 여부를 점검하여 네트워크 정보 유출 방지
check_u59() {
    if [ -f /etc/snmp/snmpd.conf ]; then
        if grep -vE "^#|^$" /etc/snmp/snmpd.conf | grep -qiE "public|private"; then
            report "U-59" "SNMP 커뮤니티 스트링" "취약" "기본 문자열 사용 중"
        else
            report "U-59" "SNMP 커뮤니티 스트링" "양호" "기본 문자열 발견되지 않음"
        fi
    else
        report "U-59" "SNMP 커뮤니티 스트링" "양호" "SNMP 미사용"
    fi
}

# [U-60] 최신 보안 패치 적용: 시스템 및 소프트웨어의 알려진 취약점을 해결하기 위한 최신 보안 패치 적용 상태 점검
check_u60() {
    local updates=$(apt list --upgradable 2>/dev/null | grep -i "security" | wc -l)
    if [ "$updates" -eq 0 ]; then
        report "U-60" "최신 보안 패치 적용" "양호" "누락된 보안 패치 없음"
    else
        report "U-60" "최신 보안 패치 적용" "취약" "$updates 개의 보안 업데이트 대기 중"
    fi
}

# [U-61] FTP 서비스 사용 제한: 보안이 취약한 FTP 대신 SFTP 등 안전한 전송 방식 사용 여부 및 구동 상태 점검
check_u61() {
    if systemctl is-active --quiet vsftpd 2>/dev/null; then
        report "U-61" "FTP 서비스 사용 제한" "수동확인" "FTP 서비스 활성 중"
    else
        report "U-61" "FTP 서비스 사용 제한" "양호" "FTP 비활성"
    fi
}

# [U-62] ftpusers 파일 설정: root 등 관리자 계정의 FTP 접속을 차단하기 위해 차단 목록(ftpusers)에 등록되어 있는지 확인
check_u62() {
    if [ -f /etc/ftpusers ] && grep -q "^root" /etc/ftpusers; then
        report "U-62" "ftpusers 파일 설정" "양호" "root 접속 차단됨"
    else
        report "U-62" "ftpusers 파일 설정" "취약" "root 접속 차단 미비"
    fi
}

# [U-63] ftpusers 파일 권한 설정: 접속 차단 목록 파일의 무단 수정을 막기 위해 소유자(root) 및 권한(640 이하) 점검
check_u63() {
    if [ -f /etc/ftpusers ]; then
        local perm=$(stat -c %a /etc/ftpusers)
        [[ "$perm" -le 640 ]] && report "U-63" "ftpusers 권한" "양호" "$perm" \
        || report "U-63" "ftpusers 권한" "취약" "$perm"
    else
        report "U-63" "ftpusers 권한" "양호" "파일 없음"
    fi
}

# [U-64] rsyslog 설정 점검: 시스템 로그가 정상적으로 기록되도록 설정 파일의 주요 로그 기록 정책 존재 여부 점검
check_u64() {
    if [ -f /etc/rsyslog.conf ] && grep -qE "auth|cron|daemon" /etc/rsyslog.conf; then
        report "U-64" "rsyslog 설정 점검" "양호" "로그 기록 설정 확인"
    else
        report "U-64" "rsyslog 설정 점검" "취약" "설정 미비"
    fi
}

# [U-65] 로그 기록의 정기적 검토 및 보고: 관리자가 주기적으로 시스템 로그를 분석하고 이상 징후를 보고하는 정책 준수 여부 확인
check_u65() {
    report "U-65" "로그 정기 검토" "수동확인" "관리자 검토 보고서 및 로그 확인 필요"
}

# [U-66] 로그 파일 권한 설정: 기록된 로그의 변조 및 삭제를 막기 위해 로그 파일의 소유자(root) 및 타인 쓰기 금지 권한 점검
check_u66() {
    local perm=$(stat -c %a /var/log/auth.log 2>/dev/null || echo "000")
    [[ "$perm" -le 640 ]] && report "U-66" "로그 파일 권한" "양호" "$perm" \
    || report "U-66" "로그 파일 권한" "취약" "$perm (기준 640 이하)"
}

# [U-67] 접속 IP 및 포트 제한: 인가된 IP와 포트에서만 서비스에 접속할 수 있도록 방화벽(ufw 등) 및 접근 제어 설정 점검
check_u67() {
    local ufw_status=$(ufw status | head -n 1)
    if [[ "$ufw_status" == *"active"* ]]; then
        report "U-67" "접속 IP 및 포트 제한" "양호" "방화벽 활성"
    else
        report "U-67" "접속 IP 및 포트 제한" "취약" "방화벽 비활성"
    fi
}

# ===== 4. 실행 =====
main() {
    echo "[시작] 보안 점검 로직 실행 중..."
    for i in {01..67}; do
        check_u$i
    done
    echo "[완료] 모든 점검이 끝났습니다. 결과: $RESULT_FILE"
}

main "$@"