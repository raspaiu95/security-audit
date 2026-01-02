import os
import re
import pandas as pd

# =========================
# 설정
# =========================
INPUT_DIR = r"C:\Users\kog\Desktop\code\script"
OUTPUT_FILE = "security_audit_result.xlsx"
TOTAL_ITEMS = 67

# =========================
# 조치방안 정의 (OS별)
# =========================
REMEDIATION_MAP = {
    "Ubuntu": {
"U-01": "root 계정 원격 접속 제한\n[SSH]\nStep 1) /etc/ssh/sshd_config 파일에서 PermitRootLogin 값을 no로 설정\nPermitRootLogin no\nStep 2) 설정 변경 후 SSH 서비스 재시작\nsystemctl restart ssh\n[Telnet]\nStep 1) Telnet 서비스 비활성화\nsystemctl disable telnet\nsystemctl stop telnet\n※ Ubuntu 20.04 이상에서는 Telnet 서비스가 기본 비활성화됨",
"U-02": "비밀번호 관리정책 설정\nStep 1) /etc/login.defs 파일에서 비밀번호 정책 설정\nPASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nStep 2) /etc/pam.d/common-password 파일에서 pam_pwquality 모듈 설정\npassword requisite pam_pwquality.so retry=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1",
"U-03": "계정 잠금 임계값 설정\nStep 1) /etc/pam.d/common-auth 파일에 pam_tally2 또는 pam_faillock 설정 추가\nauth required pam_tally2.so deny=5 unlock_time=600\n※ 로그인 실패 5회 초과 시 계정 잠금",
"U-04": "비밀번호 파일 보호\nStep 1) /etc/shadow 파일 권한 확인 및 설정\nchmod 400 /etc/shadow\nchown root:shadow /etc/shadow",
"U-05": "root 이외 UID 0 계정 금지\nStep 1) UID 0 계정 확인\nawk -F: '$3==0 {print $1}' /etc/passwd\nStep 2) root 외 계정 존재 시 UID 변경 또는 계정 삭제",
"U-06": "su 명령어 사용 제한\nStep 1) wheel 그룹 생성 및 관리자 계정만 추가\ngroupadd wheel\nusermod -aG wheel [계정명]\nStep 2) /etc/pam.d/su 파일에서 pam_wheel.so 설정\nauth required pam_wheel.so use_uid",
"U-07": "불필요한 계정 제거\nStep 1) /etc/passwd 파일에서 사용하지 않는 계정 확인\nStep 2) 불필요한 계정 삭제 또는 로그인 쉘 제한\nusermod -s /usr/sbin/nologin [계정명]",
"U-08": "관리자 그룹 최소화\nStep 1) sudo 또는 wheel 그룹 사용자 확인\ngetent group sudo\ngetent group wheel\nStep 2) 불필요한 관리자 권한 계정 제거",
"U-09": "계정이 존재하지 않는 GID 금지\nStep 1) /etc/group 및 /etc/passwd 비교\nStep 2) 사용되지 않는 GID 삭제 또는 수정",
"U-10": "동일한 UID 금지\nStep 1) UID 중복 여부 확인\ncut -d: -f3 /etc/passwd | sort | uniq -d\nStep 2) 중복 UID 계정 수정",
"U-11": "사용자 Shell 점검\nStep 1) /etc/passwd 파일에서 로그인 불필요 계정 확인\nStep 2) 시스템 계정 쉘을 nologin 또는 false로 변경\nusermod -s /usr/sbin/nologin [계정명]",
"U-12": "세션 종료 시간 설정\nStep 1) /etc/profile 또는 /etc/bash.bashrc 파일에 TMOUT 설정\nTMOUT=600\nexport TMOUT\nStep 2) 설정 파일 권한 변경 방지",
"U-13": "안전한 비밀번호 암호화 알고리즘 사용\nStep 1) /etc/login.defs 파일에서 암호화 방식 확인\nENCRYPT_METHOD SHA512\nStep 2) 기존 계정 비밀번호 변경 유도",
"U-14": "root 홈 디렉터리 및 PATH 권한 설정\nStep 1) root 홈 디렉터리 권한 설정\nchmod 700 /root\nStep 2) PATH 변수에 '.' 포함 여부 제거",
"U-15": "파일 및 디렉터리 소유자 설정\nStep 1) 소유자 없는 파일 검색\nfind / -nouser -o -nogroup\nStep 2) 적절한 소유자 지정",
"U-16": "/etc/passwd 파일 권한 설정\nStep 1) 권한 및 소유자 설정\nchmod 644 /etc/passwd\nchown root:root /etc/passwd",
"U-17": "시스템 시작 스크립트 권한 설정\nStep 1) /etc/init.d 및 systemd 서비스 파일 권한 점검\nchmod 755 /etc/init.d/*\nStep 2) 불필요한 수정 권한 제거",
"U-18": "/etc/shadow 파일 소유자 및 권한 설정\nStep 1) 권한 설정\nchmod 400 /etc/shadow\nchown root:shadow /etc/shadow",
"U-19": "/etc/hosts 파일 소유자 및 권한 설정\nStep 1) 권한 설정\nchmod 644 /etc/hosts\nchown root:root /etc/hosts",
"U-20": "/etc/inetd.conf 또는 xinetd 설정 파일 권한 설정\nStep 1) 파일 존재 여부 확인\nls /etc/inetd.conf /etc/xinetd.conf\nStep 2) 권한 설정\nchmod 600 해당파일\nchown root:root 해당파일",
"U-21": "/etc/syslog.conf 또는 rsyslog 설정 파일 권한 설정\nStep 1) rsyslog 설정 파일 확인\nls /etc/rsyslog.conf\nStep 2) 권한 및 소유자 설정\nchmod 640 /etc/rsyslog.conf\nchown root:adm /etc/rsyslog.conf",
"U-22": "/etc/services 파일 소유자 및 권한 설정\nStep 1) 권한 설정\nchmod 644 /etc/services\nchown root:root /etc/services",
"U-23": "SUID, SGID, Sticky bit 설정 파일 점검\nStep 1) SUID/SGID 파일 검색\nfind / -perm /6000 -type f 2>/dev/null\nStep 2) 불필요한 파일의 SUID/SGID 제거\nchmod -s 대상파일",
"U-24": "사용자 및 시스템 환경변수 파일 권한 설정\nStep 1) /etc/profile, /etc/bash.bashrc 권한 확인\nStep 2) 권한 설정\nchmod 644 환경변수파일\nchown root:root 환경변수파일",
"U-25": "world writable 파일 점검\nStep 1) world writable 파일 검색\nfind / -perm -2 -type f 2>/dev/null\nStep 2) 불필요한 쓰기 권한 제거\nchmod o-w 대상파일",
"U-26": "/dev 디렉터리 내 불필요한 device 파일 점검\nStep 1) /dev 내 비정상 파일 확인\nfind /dev -type f\nStep 2) 불필요한 device 파일 삭제",
"U-27": ".rhosts 및 hosts.equiv 사용 금지\nStep 1) 파일 존재 여부 확인\nfind / -name .rhosts -o -name hosts.equiv 2>/dev/null\nStep 2) 해당 파일 삭제",
"U-28": "접속 IP 및 포트 제한 설정\nStep 1) /etc/hosts.allow, /etc/hosts.deny 설정\nALL: ALL 설정 후 허용 IP만 allow 등록\nStep 2) 방화벽(UFW) 정책 적용\nufw enable",
"U-29": "hosts.lpd 파일 소유자 및 권한 설정\nStep 1) 파일 존재 여부 확인\nls /etc/hosts.lpd\nStep 2) 권한 설정\nchmod 600 /etc/hosts.lpd\nchown root:root /etc/hosts.lpd",
"U-30": "UMASK 설정 관리\nStep 1) /etc/profile 및 /etc/login.defs 파일 설정\numask 022 또는 umask 027\nStep 2) 사용자별 .bashrc 확인",
"U-31": "홈 디렉터리 소유자 및 권한 설정\nStep 1) 사용자 홈 디렉터리 권한 점검\nls -ld /home/*\nStep 2) 권한 설정\nchmod 750 홈디렉터리\nchown 사용자:사용자 홈디렉터리",
"U-32": "홈 디렉터리로 지정된 디렉터리 존재 여부 점검\nStep 1) /etc/passwd 기준 홈 디렉터리 확인\nStep 2) 존재하지 않는 디렉터리 생성 또는 계정 수정",
"U-33": "숨겨진 파일 및 디렉터리 점검\nStep 1) 숨김 파일 검색\nfind /home -name \".*\"\nStep 2) 불필요한 파일 삭제",
"U-34": "Finger 서비스 비활성화\nStep 1) 서비스 상태 확인\nsystemctl status finger\nStep 2) 서비스 중지 및 비활성화\nsystemctl stop finger\nsystemctl disable finger",
"U-35": "공유 서비스 익명 접근 제한\nStep 1) Samba/NFS 설정 점검\nStep 2) guest ok = no 설정 적용",
"U-36": "r 계열 서비스 비활성화\nStep 1) rsh, rlogin, rexec 서비스 확인\nStep 2) 패키지 제거 또는 서비스 비활성화\napt remove rsh-server",
"U-37": "crontab 설정 파일 권한 설정\nStep 1) /etc/crontab 권한 설정\nchmod 600 /etc/crontab\nchown root:root /etc/crontab\nStep 2) cron.allow 설정",
"U-38": "DoS 공격에 취약한 서비스 비활성화\nStep 1) 불필요한 네트워크 서비스 점검\nStep 2) 사용하지 않는 서비스 중지 및 제거",
"U-39": "불필요한 NFS 서비스 비활성화\nStep 1) NFS 서비스 상태 확인\nsystemctl status nfs-server\nStep 2) 서비스 중지 및 비활성화\nsystemctl stop nfs-server\nsystemctl disable nfs-server",
"U-40": "NFS 접근 통제 설정\nStep 1) /etc/exports 설정\n허용 IP만 export 설정\nStep 2) 설정 적용\nexportfs -ra",
"U-41": "불필요한 automountd 서비스 비활성화\nStep 1) 서비스 상태 확인\nsystemctl status autofs\nStep 2) 서비스 중지 및 비활성화\nsystemctl stop autofs\nsystemctl disable autofs",
"U-42": "불필요한 RPC 서비스 비활성화\nStep 1) rpcbind 서비스 확인\nsystemctl status rpcbind\nStep 2) 서비스 중지 및 비활성화\nsystemctl stop rpcbind\nsystemctl disable rpcbind",
"U-43": "NIS, NIS+ 서비스 비활성화\nStep 1) NIS 관련 패키지 확인\ndpkg -l | grep nis\nStep 2) 패키지 제거 또는 서비스 중지\napt remove nis",
"U-44": "tftp, talk 서비스 비활성화\nStep 1) 서비스 설치 여부 확인\nsystemctl status tftpd-hpa\nStep 2) 서비스 중지 및 제거\nsystemctl stop tftpd-hpa\napt remove tftpd-hpa",
"U-45": "메일 서비스 버전 점검\nStep 1) 메일 서비스(Postfix 등) 설치 여부 확인\npostconf -d\nStep 2) 최신 버전 유지 및 불필요 시 제거",
"U-46": "일반 사용자의 메일 서비스 실행 제한\nStep 1) 메일 서비스 실행 권한 확인\nStep 2) root 사용자만 실행 가능하도록 설정",
"U-47": "스팸 메일 릴레이 제한 설정\nStep 1) Postfix relay 설정 확인\nsmtpd_recipient_restrictions 설정\nStep 2) 외부 릴레이 차단 설정 적용",
"U-48": "expn, vrfy 명령어 제한\nStep 1) Postfix 설정 파일 수정\nStep 2) disable_vrfy_command = yes 설정",
"U-49": "DNS 보안 패치 적용\nStep 1) DNS(BIND) 버전 확인\nnamed -v\nStep 2) 최신 보안 패치 적용\napt update && apt upgrade bind9",
"U-50": "DNS Zone Transfer 제한\nStep 1) named.conf 설정\nallow-transfer { 허용IP; } 설정\nStep 2) 설정 적용 후 재시작\nsystemctl restart bind9",
"U-51": "DNS 동적 업데이트 설정 제한\nStep 1) allow-update 설정 점검\nStep 2) 불필요한 동적 업데이트 비활성화",
"U-52": "Telnet 서비스 비활성화\nStep 1) Telnet 서비스 확인\nsystemctl status telnet\nStep 2) 서비스 제거\napt remove telnetd",
"U-53": "FTP 서비스 정보 노출 제한\nStep 1) FTP 배너 설정 확인\nStep 2) 서버 정보 노출 제한 설정",
"U-54": "암호화되지 않은 FTP 서비스 비활성화\nStep 1) FTP 서비스 사용 여부 확인\nStep 2) FTP 제거 또는 SFTP 사용 전환",
"U-55": "FTP 계정 Shell 제한\nStep 1) FTP 계정 shell 확인\nStep 2) /sbin/nologin 또는 /bin/false 설정",
"U-56": "FTP 서비스 접근 제어 설정\nStep 1) vsftpd.conf 설정\nuserlist_enable=YES\nStep 2) 허용 사용자만 접근 가능하도록 설정",
"U-57": "ftpusers 파일 설정\nStep 1) /etc/ftpusers 파일 생성 또는 확인\nStep 2) root 등 시스템 계정 등록",
"U-58": "불필요한 SNMP 서비스 비활성화\nStep 1) snmpd 서비스 확인\nsystemctl status snmpd\nStep 2) 서비스 중지 및 제거\nsystemctl stop snmpd\napt remove snmpd",
"U-59": "안전한 SNMP 버전 사용\nStep 1) SNMPv1, v2 비활성화\nStep 2) SNMPv3 사용 설정",
"U-60": "SNMP Community String 복잡성 설정\nStep 1) 기본 community string 제거\nStep 2) 추측 불가능한 값으로 변경",
"U-61": "SNMP Access Control 설정\nStep 1) 접근 허용 IP 제한\nStep 2) ACL 기반 접근 통제 적용",
"U-62": "로그인 시 경고 메시지 설정\nStep 1) /etc/issue, /etc/issue.net 설정\nStep 2) 불법 접근 경고 문구 작성",
"U-63": "sudo 명령어 접근 관리\nStep 1) /etc/sudoers 파일 점검\nStep 2) 최소 권한 원칙 기반 사용자만 등록",
"U-64": "주기적인 보안 패치 적용\nStep 1) 패키지 최신화\napt update && apt upgrade\nStep 2) 자동 보안 업데이트 설정",
"U-65": "NTP 및 시각 동기화 설정\nStep 1) timedatectl 설정 확인\nStep 2) NTP 활성화\ntimedatectl set-ntp true",
"U-66": "정책에 따른 시스템 로깅 설정\nStep 1) rsyslog 설정 점검\nStep 2) 로그 수준 및 대상 설정 강화",
"U-67": "로그 디렉터리 소유자 및 권한 설정\nStep 1) /var/log 권한 확인\nStep 2) 권한 설정\nchmod 750 /var/log\nchown root:root /var/log"
    },
    "Rocky": {
"U-01": "root 계정 원격 접속 제한\n[조치방안]\nStep 1) /etc/ssh/sshd_config 파일에서 PermitRootLogin no 설정\nStep 2) systemctl restart sshd\nStep 3) Telnet 사용 시 /etc/pam.d/login에 auth required pam_securetty.so 추가",
"U-02": "비밀번호 관리정책 설정\n[조치방안]\nStep 1) /etc/security/pwquality.conf에서 minlen=8, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1 설정\nStep 2) /etc/pam.d/system-auth, password-auth에 pam_pwquality.so 적용 확인",
"U-03": "계정 잠금 임계값 설정\n[조치방안]\nStep 1) /etc/security/faillock.conf에서 deny=5, unlock_time=600 설정\nStep 2) /etc/pam.d/system-auth 및 password-auth에 pam_faillock.so 모듈 적용 확인",
"U-04": "비밀번호 파일 보호\n[조치방안]\nStep 1) /etc/passwd 권한 644, 소유자 root 확인\nStep 2) /etc/shadow 권한 000 또는 400, 소유자 root 확인 (chmod 400 /etc/shadow)",
"U-05": "root 이외의 UID가 ‘0’ 금지\n[조치방안]\nStep 1) awk -F: '$3==0 {print $1}' /etc/passwd 명령으로 root 외 계정 확인\nStep 2) 존재 시 UID 변경(usermod -u) 또는 계정 삭제",
"U-06": "사용자 계정 su 기능 제한\n[조치방안]\nStep 1) /etc/pam.d/su 파일에서 auth required pam_wheel.so use_uid 주석 제거\nStep 2) su 권한이 필요한 계정만 wheel 그룹에 추가 (usermod -aG wheel [계정명])",
"U-07": "불필요한 계정 제거\n[조치방안]\nStep 1) lp, uucp, nuucp 등 미사용 시스템 계정 확인\nStep 2) userdel [계정명] 또는 /etc/passwd에서 쉘을 /sbin/nologin으로 변경",
"U-08": "관리자 그룹에 최소한의 계정 포함\n[조치방안]\nStep 1) /etc/group 파일에서 root, wheel 그룹 내 불필요한 계정 삭제\nStep 2) 관리 권한이 필요한 인원만 최소한으로 유지",
"U-09": "계정이 존재하지 않는 GID 금지\n[조치방안]\nStep 1) /etc/group 파일에서 소속된 계정이 없는 불필요한 그룹 삭제 (groupdel [그룹명])",
"U-10": "동일한 UID 금지\n[조치방안]\nStep 1) /etc/passwd에서 UID 중복 여부 확인\nStep 2) 중복된 UID가 있을 경우 유일한 UID로 수정",
"U-11": "사용자 Shell 점검\n[조치방안]\nStep 1) /etc/passwd에서 로그인이 필요 없는 서비스 계정 확인\nStep 2) 해당 계정들의 쉘을 /sbin/nologin 또는 /bin/false로 변경",
"U-12": "세션 종료 시간 설정\n[조치방안]\nStep 1) /etc/profile 또는 /etc/bashrc 파일에 TMOUT=600 (10분) 추가\nStep 2) export TMOUT 설정 확인",
"U-13": "안전한 비밀번호 암호화 알고리즘 사용\n[조치방안]\nStep 1) /etc/login.defs에서 ENCRYPT_METHOD SHA512 설정 확인\nStep 2) authconfig --test | grep hashing 명령으로 sha512 적용 여부 확인",
"U-14": "root 홈, 패스 디렉터리 권한 및 패스 설정\n[조치방안]\nStep 1) root 홈 디렉토리(/root) 권한 700 확인\nStep 2) /etc/profile 등에서 PATH 환경변수에 \".\"(현재 디렉토리)이 맨 앞이나 중간에 포함되지 않도록 수정",
"U-15": "파일 및 디렉터리 소유자 설정\n[조치방안]\nStep 1) find / -nouser -o -nogroup 명령으로 소유자 없는 파일 검색\nStep 2) 검색된 파일에 적절한 소유자 할당 또는 삭제",
"U-16": "/etc/passwd 파일 소유자 및 권한 설정\n[조치방안]\nStep 1) chown root /etc/passwd\nStep 2) chmod 644 /etc/passwd",
"U-17": "시스템 시작 스크립트 권한 설정\n[조치방안]\nStep 1) /etc/rc.d/init.d/ 등 시작 스크립트 디렉토리 소유자 root 확인\nStep 2) 타인(Other)에게 쓰기 권한 제거 (chmod o-w)",
"U-18": "/etc/shadow 파일 소유자 및 권한 설정\n[조치방안]\nStep 1) chown root /etc/shadow\nStep 2) chmod 400 /etc/shadow (또는 000)",
"U-19": "/etc/hosts 파일 소유자 및 권한 설정\n[조치방안]\nStep 1) chown root /etc/hosts\nStep 2) chmod 644 /etc/hosts",
"U-20": "/etc/(x)inetd.conf 파일 소유자 및 권한 설정\n[조치방안]\nStep 1) Rocky 8/9는 xinetd를 기본으로 쓰지 않으나, 존재 시 chown root /etc/xinetd.conf\nStep 2) chmod 600 /etc/xinetd.conf",
"U-21": "/etc/(r)syslog.conf 파일 소유자 및 권한 설정\n[조치방안]\nStep 1) chown root /etc/rsyslog.conf\nStep 2) chmod 640 /etc/rsyslog.conf (또는 644)",
"U-22": "/etc/services 파일 소유자 및 권한 설정\n[조치방안]\nStep 1) chown root /etc/services\nStep 2) chmod 644 /etc/services",
"U-23": "SUID, SGID, Sticky bit 설정 파일 점검\n[조치방안]\nStep 1) find / -user root -type f \\( -perm -4000 -o -perm -2000 \\) 명령으로 점검\nStep 2) 불필요한 SUID/SGID 제거 (chmod -s [파일명])",
"U-24": "사용자, 시스템 환경변수 파일 소유자 및 권한 설정\n[조치방안]\nStep 1) /etc/profile, .bashrc 등 환경변수 파일 소유자 root 및 해당 사용자 확인\nStep 2) 권한 644 이하 설정 (chmod 644 [파일명])",
"U-25": "world writable 파일 점검\n[조치방안]\nStep 1) find / -type f -perm -2 -exec ls -l {} \\; 명령으로 검색\nStep 2) 일반 사용자의 쓰기 권한 제거 (chmod o-w [파일명])",
"U-26": "/dev에 존재하지 않는 device 파일 점검\n[조치방안]\nStep 1) find /dev -type f ! -name \"console\" ! -name \"null\" ! -name \"zero\" -exec ls -l {} \\; 로 점검\nStep 2) 비정상적인 일반 파일 존재 시 삭제",
"U-27": "$HOME/.rhosts, hosts.equiv 사용 금지\n[조치방안]\nStep 1) /etc/hosts.equiv 및 각 사용자 홈 디렉토리 내 .rhosts 파일 삭제\nStep 2) 해당 파일이 필요한 경우 권한을 600으로 제한하고 관리자 승인 하에 사용",
"U-28": "접속 IP 및 포트 제한\n[조치방안]\nStep 1) /etc/hosts.allow 및 /etc/hosts.deny 설정 또는 firewalld 서비스 이용\nStep 2) firewall-cmd --list-all 명령으로 허용된 서비스 및 IP 대역 확인 및 제한",
"U-29": "hosts.lpd 파일 소유자 및 권한 설정\n[조치방안]\nStep 1) /etc/hosts.lpd 파일 존재 시 소유자 root 확인\nStep 2) 권한 600으로 설정 (chmod 600 /etc/hosts.lpd)",
"U-30": "UMASK 설정 관리\n[조치방안]\nStep 1) /etc/profile 또는 /etc/bashrc에서 UMASK 022 또는 027 설정 확인\nStep 2) 적용 후 새로운 파일 생성 시 권한이 적절한지 확인",
"U-31": "홈 디렉토리 소유자 및 권한 설정\n[조치방안]\nStep 1) 각 사용자 홈 디렉토리 소유자가 해당 사용자인지 확인\nStep 2) 홈 디렉토리 권한 700 이하 설정 (chmod 700 /home/[사용자])",
"U-32": "홈 디렉토리로 지정한 디렉토리의 존재 관리\n[조치방안]\nStep 1) /etc/passwd에 설정된 홈 디렉토리 실제 존재 여부 확인\nStep 2) 존재하지 않는 경우 디렉토리 생성 또는 계정 정보 수정",
"U-33": "숨겨진 파일 및 디렉토리 검색 및 제거\n[조치방안]\nStep 1) find / -name \".*\" -type f 또는 -type d 명령으로 불필요한 숨김 파일 검색\nStep 2) 의심스러운 숨겨진 파일 및 디렉토리 조사 후 삭제",
"U-34": "Finger 서비스 비활성화\n[조치방안]\nStep 1) systemctl stop finger (설치된 경우)\nStep 2) systemctl disable finger 또는 dnf remove finger-server",
"U-35": "공유 서비스에 대한 익명 접근 제한 설정\n[조치방안]\nStep 1) Samba 설정(/etc/samba/smb.conf)에서 guest ok = no 설정\nStep 2) NFS 설정에서 anonymous 접근 허용 여부 점검",
"U-36": "r 계열 서비스 비활성화\n[조치방안]\nStep 1) rsh, rlogin, rexec 서비스 중지\nStep 2) systemctl disable [서비스명].socket 또는 해당 패키지 제거",
"U-37": "crontab 설정파일 권한 설정 미흡\n[조치방안]\nStep 1) /etc/crontab 및 /var/spool/cron/* 권한 600 설정\nStep 2) /etc/cron.allow, /etc/cron.deny 파일 소유자 및 권한(640 이하) 점검",
"U-38": "DoS 공격에 취약한 서비스 비활성화\n[조치방안]\nStep 1) echo, discard, daytime, chargen 등 불필요한 서비스 비활성화\nStep 2) systemctl stop 및 disable 처리",
"U-39": "불필요한 NFS 서비스 비활성화\n[조치방안]\nStep 1) NFS 미사용 시 systemctl stop nfs-server rpcbind\nStep 2) systemctl disable nfs-server rpcbind",
"U-40": "NFS 접근 통제\n[조치방안]\nStep 1) /etc/exports 파일에서 접근 허용 IP 제한 설정\nStep 2) root_squash 옵션 적용 여부 확인",
"U-41": "불필요한 automountd 제거\n[조치방안]\nStep 1) systemctl stop autofs\nStep 2) systemctl disable autofs (미사용 시 패키지 제거 권장)",
"U-42": "불필요한 RPC 서비스 비활성화\n[조치방안]\nStep 1) rpc.cmsd, rpc.ttdbserverd 등 불필요한 RPC 서비스 확인\nStep 2) /etc/xinetd.d/ 내 해당 서비스 disable = yes 설정 또는 systemctl stop rpcbind",
"U-43": "NIS, NIS+ 점검\n[조치방안]\nStep 1) systemctl stop ypserv ypbind yppasswdd\nStep 2) systemctl disable ypserv ypbind yppasswdd (NIS 미사용 시 관련 패키지 삭제)",
"U-44": "tftp, talk 서비스 비활성화\n[조치방안]\nStep 1) systemctl stop tftp talk\nStep 2) systemctl disable tftp talk 또는 dnf remove tftp-server talk-server",
"U-45": "메일 서비스 버전 점검\n[조치방안]\nStep 1) dnf info sendmail 또는 dnf info postfix 명령으로 버전 확인\nStep 2) 최신 보안 패치 적용 또는 최신 버전 업데이트",
"U-46": "일반 사용자의 메일 서비스 실행 방지\n[조치방안]\nStep 1) Sendmail 사용 시 /etc/mail/sendmail.cf에서 PrivacyOptions에 restrictqrun 설정 추가\nStep 2) Postfix 사용 시 일반 사용자 큐 접근 제한 설정",
"U-47": "스팸 메일 릴레이 제한\n[조치방안]\nStep 1) Sendmail: /etc/mail/access 파일에서 릴레이 허용 IP 제한\nStep 2) Postfix: main.cf에서 smtpd_relay_restrictions 또는 mynetworks 설정으로 제한",
"U-48": "expn, vrfy 명령어 제한\n[조치방안]\nStep 1) /etc/mail/sendmail.cf에서 PrivacyOptions에 noexpn, novrfy 추가\nStep 2) Postfix의 경우 disable_vrfy_command = yes 설정",
"U-49": "DNS 보안 버전 패치\n[조치방안]\nStep 1) named -v 명령으로 버전 확인\nStep 2) dnf update bind 명령을 통해 최신 보안 패치 적용",
"U-50": "DNS Zone Transfer 설정\n[조치방안]\nStep 1) /etc/named.conf 파일의 options 또는 zone 섹션에 allow-transfer { none; }; 설정\nStep 2) 특정 보조 네임서버만 허용하도록 IP 명시",
"U-51": "DNS 서비스의 취약한 동적 업데이트 설정 금지\n[조치방안]\nStep 1) /etc/named.conf 파일의 zone 설정에서 allow-update { none; }; 확인\nStep 2) 불필요한 동적 업데이트 기능 비활성화",
"U-52": "Telnet 서비스 비활성화\n[조치방안]\nStep 1) systemctl stop telnet.socket\nStep 2) systemctl disable telnet.socket (가급적 SSH 사용 권장)",
"U-53": "FTP 서비스 정보 노출 제한\n[조치방안]\nStep 1) vsftpd 사용 시 /etc/vsftpd/vsftpd.conf에서 ftpd_banner 설정\nStep 2) 배너 내용에 서버 버전 및 시스템 정보 노출 금지",
"U-54": "암호화되지 않는 FTP 서비스 비활성화\n[조치방안]\nStep 1) FTP 미사용 시 서비스 중지 및 패키지 삭제\nStep 2) 사용 시 SFTP 또는 FTPS(SSL/TLS) 적용 권장",
"U-55": "FTP 계정 Shell 제한\n[조치방안]\nStep 1) /etc/passwd에서 ftp 계정의 쉘을 /sbin/nologin으로 설정\nStep 2) FTP 전용 계정 외에는 로그인 쉘 부여 금지",
"U-56": "FTP 서비스 접근 제어 설정\n[조치방안]\nStep 1) /etc/vsftpd/vsftpd.conf에서 tcp_wrappers=YES 또는 별도 ACL 설정\nStep 2) /etc/hosts.allow, /etc/hosts.deny를 통한 접근 IP 제한",
"U-57": "Ftpusers 파일 설정\n[조치방안]\nStep 1) /etc/vsftpd/ftpusers 및 /etc/vsftpd/user_list에 root 계정 포함 확인\nStep 2) 시스템 관리 계정의 FTP 접속 제한",
"U-58": "불필요한 SNMP 서비스 구동 점검\n[조치방안]\nStep 1) SNMP 미사용 시 systemctl stop snmpd\nStep 2) systemctl disable snmpd",
"U-59": "안전한 SNMP 버전 사용\n[조치방안]\nStep 1) SNMPv1, v2c 사용 금지 및 SNMPv3 사용 설정 권장\nStep 2) /etc/snmp/snmpd.conf에서 버전 설정 확인",
"U-60": "SNMP Community String 복잡성 설정\n[조치방안]\nStep 1) public, private 등 기본 문자열 삭제\nStep 2) 대문자, 소문자, 숫자, 특수문자가 조합된 복잡한 문자열로 변경",
"U-61": "SNMP Access Control 설정\n[조치방안]\nStep 1) SNMP 설정 파일에서 특정 관리자 IP로만 접근(rocommunity 등) 제한\nStep 2) SNMP 포트(161/UDP) 방화벽 제한",
"U-62": "로그인 시 경고 메시지 설정\n[조치방안]\nStep 1) /etc/issue, /etc/issue.net, /etc/motd 파일에 법적 경고 문구 작성\nStep 2) SSH 접속 시 배너가 표시되도록 sshd_config 설정",
"U-63": "sudo 명령어 접근 관리\n[조치방안]\nStep 1) visudo 명령으로 /etc/sudoers 파일 점검\nStep 2) 불필요한 사용자나 그룹에 대한 ALL 권한 할당 여부 확인 및 제거",
"U-64": "주기적 보안 패치 및 벤더 권고사항 적용\n[조치방안]\nStep 1) dnf check-update 명령으로 보안 패치 확인\nStep 2) dnf update --security 명령을 통한 주기적 업데이트",
"U-65": "NTP 및 시각 동기화 설정\n[조치방안]\nStep 1) chrony 서비스 사용 시 /etc/chrony.conf에서 신뢰할 수 있는 NTP 서버 설정\nStep 2) systemctl enable --now chronyd 명령으로 서비스 구동",
"U-66": "정책에 따른 시스템 로깅 설정\n[조치방안]\nStep 1) /etc/rsyslog.conf 파일에 *.info;authpriv.none;cron.none 등 로그 저장 설정 확인\nStep 2) rsyslog 서비스 재시작하여 정책 반영",
"U-67": "로그 디렉터리 소유자 및 권한 설정\n[조치방안]\nStep 1) /var/log 디렉터리 및 하위 로그 파일 소유자 root 확인\nStep 2) 권한 750(디렉터리), 600(파일) 등 최소 권한 설정 (chmod 600 /var/log/messages)"
    }
}

# =========================
# 정규식 설정
# =========================
DATE_PATTERN = re.compile(r"점검 일시:\s*(.+)")
ITEM_PATTERN = re.compile(r"\[(U-\d+)\]\s*(.+)")
RESULT_PATTERN = re.compile(r"- 결과:\s*(.+)")
REASON_PATTERN = re.compile(r"- 근거:\s*(.+)")

# 파일명 예시: 192.168.1.10@@hostname@@Rocky_8.6.txt
FILENAME_PATTERN = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)@@.+?@@(?P<os>Ubuntu|Rocky)_(?P<version>[\d.]+)",
    re.IGNORECASE
)

rows = []

# =========================
# TXT 파일 파싱
# =========================
if not os.path.exists(INPUT_DIR):
    print(f"[오류] 경로를 찾을 수 없습니다: {INPUT_DIR}")
else:
    for file_name in os.listdir(INPUT_DIR):
        if not file_name.lower().endswith(".txt"):
            continue

        m = FILENAME_PATTERN.search(file_name)
        if not m:
            continue

        ip_addr = m.group("ip")
        os_name = m.group("os")
        os_info = f"{os_name} {m.group('version')}"

        with open(os.path.join(INPUT_DIR, file_name), encoding="utf-8") as f:
            lines = f.readlines()

        check_date = ""
        item_id = item_name = result = reason = ""

        for line in lines:
            line = line.strip()

            # 점검 일시 추출
            if not check_date:
                dt_m = DATE_PATTERN.search(line)
                if dt_m:
                    check_date = dt_m.group(1)

            # 항목 ID 및 항목명 추출
            itm_m = ITEM_PATTERN.search(line)
            if itm_m:
                item_id, item_name = itm_m.group(1), itm_m.group(2)
                continue

            # 결과 추출
            res_m = RESULT_PATTERN.search(line)
            if res_m:
                result = res_m.group(1)
                continue

            # 근거 추출 및 데이터 행 추가
            rea_m = REASON_PATTERN.search(line)
            if rea_m:
                reason = rea_m.group(1)
                remediation = REMEDIATION_MAP.get(os_name, {}).get(item_id, "조치방안 정보 없음")

                rows.append({
                    "점검일시": check_date,
                    "OS": os_info,
                    "IP": ip_addr,
                    "항목ID": item_id,
                    "점검항목": item_name,
                    "결과": result,
                    "근거": reason,
                    "조치방안": remediation
                })

# =========================
# 데이터 집계 및 엑셀 생성
# =========================
if rows:
    df_raw = pd.DataFrame(rows)
    cols_to_check = ["양호", "취약", "수동확인"]

    # 1. 항목별 결과 집계
    item_summary = df_raw.pivot_table(
        index=["항목ID", "점검항목"],
        columns="결과",
        values="IP",
        aggfunc="count",
        fill_value=0
    ).reset_index()

    for col in cols_to_check:
        if col not in item_summary.columns:
            item_summary[col] = 0
    item_summary["전체"] = item_summary[cols_to_check].sum(axis=1)

    # 2. 서버별 준수율
    server_summary = df_raw.pivot_table(
        index=["IP", "OS"],
        columns="결과",
        values="항목ID",
        aggfunc="count",
        fill_value=0
    ).reset_index()

    for col in cols_to_check:
        if col not in server_summary.columns:
            server_summary[col] = 0

    server_summary["전체항목"] = TOTAL_ITEMS
    server_summary["준수율(%)"] = server_summary.apply(
        lambda x: round((x["양호"] / TOTAL_ITEMS) * 100, 2) if TOTAL_ITEMS > 0 else 0, axis=1
    )

    # 엑셀 저장
    with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as writer:
        df_raw.to_excel(writer, sheet_name="RawData", index=False)
        item_summary.to_excel(writer, sheet_name="항목별_결과집계", index=False)
        server_summary.to_excel(writer, sheet_name="서버별_준수율", index=False)

    print(f"[완료] 엑셀 파일이 생성되었습니다: {OUTPUT_FILE}")
else:
    print("[경고] 파싱된 데이터가 없습니다. 파일명이나 파일 내용을 확인하세요.")