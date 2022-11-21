#!/bin/bash
# Copyright 2022 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0


check_1() {
  logit ""
  local id="1"
  local desc="Host Configuration"
  checkHeader="$id - $desc"
  info "$checkHeader"
  startsectionjson "$id" "$desc"
}

check_1_1() {
  local id="1.1"
  local desc="Linux Hosts Specific Configuration"
  local check="$id - $desc"
  info "$check"
}

check_1_1_1() {
  local id="1.1.1"
  local desc="Ensure a separate partition for containers has been created (Automated)"
  local remediation="For new installations, you should create a separate partition for the /var/lib/containers mount point. For systems that have already been installed, you should use the Logical Volume Manager (LVM) within Linux to create a new partition."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  containerd_root_dir=$(containerd config default | awk '$1=="root" {print $3}' | tr -d \")

  if mountpoint -q -- "$containerd_root_dir" >/dev/null 2>&1; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  warn -c "$check"
  logcheckresult "WARN"
}

check_1_1_2() {
  local id="1.1.2"
  local desc="Ensure only trusted users are allowed to control containerd daemon (Automated)"
  local remediation="You should remove any untrusted users from the containerd group using command sudo gpasswd -d <your-user> containerd or add trusted users to the containerd group using command sudo usermod -aG containerd <your-user>. You should not create a mapping of sensitive directories from the host to container volumes."
  local remediationImpact="Only trust user are allow to build and execute containers as normal user."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  containerd_users=$(grep 'containerd' /etc/group)
  if command -v getent >/dev/null 2>&1; then
    containerd_users=$(getent group containerd)
  fi
  containerd_users=$(printf "%s" "$containerd_users" | awk -F: '{print $4}')

  local doubtfulusers=""
  if [ -n "$containerdtrustusers" ]; then
    for u in $(printf "%s" "$containerd_users" | sed "s/,/ /g"); do
      if ! printf "%s" "$containerdtrustusers" | grep -q "$u" ; then
        doubtfulusers="$u"
        if [ -n "${doubtfulusers}" ]; then
          doubtfulusers="${doubtfulusers},$u"
        fi
      fi
    done
  else
    note -s "$check"
    note "      * Users: $containerd_users"
    logcheckresult "NOTE" "doubtfulusers" "$containerd_users"
  fi

  if [ -n "${doubtfulusers}" ]; then
    warn -c "$check"
    warn "      * Doubtful users: $doubtfulusers"
    logcheckresult "WARN" "doubtfulusers" "$doubtfulusers"
  fi

  if [ -z "${doubtfulusers}" ] && [ -n "${containerdtrustusers}" ]; then
    pass -s "$check"
    logcheckresult "PASS"
  fi
}

#check_1_1_3() {
#  local id="1.1.3"
#  local desc="Ensure auditing is configured for the Docker daemon (Automated)"
#  Testcase not applicable for containerd"
#}

check_1_1_4() {
  local id="1.1.4"
  local desc="Ensure auditing is configured for containerd files and directories -/run/containerd (Automated)"
  local remediation="Install auditd. Add -a exit,always -F path=/run/containerd -F perm=war -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="/run/containerd"
  if command -v auditctl >/dev/null 2>&1; then
    if auditctl -l | grep "$file" >/dev/null 2>&1; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  warn -c "$check"
  logcheckresult "WARN"
}

check_1_1_5() {
  local id="1.1.5"
  local desc="Ensure auditing is configured for containerd files and directories - /var/lib/containerd (Automated)"
  local remediation="Install auditd. Add -w /var/lib/containerd -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  directory="/var/lib/containerd"
  if [ -d "$directory" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $directory >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$directory" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "       * Directory not found"
  logcheckresult "NOTE" "Directory not found"
}

check_1_1_6() {
  local id="1.1.6"
  local desc="Ensure auditing is configured for containerd files and directories - /etc/containerd (Automated)"
  local remediation="Install auditd. Add -w /etc/containerd -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  directory="/etc/containerd"
  if [ -d "$directory" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $directory >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$directory" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "       * Directory not found"
  logcheckresult "NOTE" "Directory not found"
}

check_1_1_7() {
  local id="1.1.7"
  local desc="Ensure auditing is configured for containerd files and directories - containerd.service (Automated)"
  local remediation="Install auditd. Add -w $(get_service_file containerd.service) -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="$(get_service_file containerd.service)"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep "$file" >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "       * File not found"
  logcheckresult "NOTE" "File not found"
}

check_1_1_8() {
  local id="1.1.8"
  local desc="Ensure auditing is configured for containerd files and directories - containerd.sock (Automated)"
  local remediation="Install auditd. Add -w $(get_service_file containerd.sock) -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="$(get_service_file containerd.sock)"
  if [ "test -e $file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep "$file" >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "       * File not found"
  logcheckresult "NOTE" "File not found"
}
check_1_1_9() {
  local id="1.1.9"
  local desc="Ensure auditing is configured for containerd files and directories - containerd.socket (Automated)"
  local remediation="Install auditd. Add -w $(get_service_file containerd.socket) -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="$(get_service_file containerd.socket)"
  if [ -e "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep "$file" >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "       * File not found"
  logcheckresult "NOTE" "File not found"
}

check_1_1_10() {
  local id="1.1.10"
  local desc="Ensure auditing is configured for containerd files and directories - /etc/default/containerd (Automated)"
  local remediation="Install auditd. Add -w /etc/default/containerd -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="/etc/default/containerd"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "       * File not found"
  logcheckresult "NOTE" "File not found"
}

#check_1_1_11() {
#  local id="1.1.11"
#  local desc="Ensure auditing is configured for Dockerfiles and directories - /etc/docker/daemon.json (Automated)"
#  Testcase not applicable for containerd"
#}

check_1_1_12() {
  local id="1.1.12"
  local desc="1.1.12 Ensure auditing is configured for containerd files and directories - /etc/containerd/config.toml (Automated)"
  local remediation="Install auditd. Add -w /etc/containerd/config.toml -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="/etc/containerd/config.toml"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "       * File not found"
  logcheckresult "NOTE" "File not found"
}

#check_1_1_13() {
#  local id="1.1.13"
#  local desc="Ensure auditing is configured for Docker files and directories - /etc/sysconfig/docker (Automated)"
#  Testcase not applicable for containerd"
#}


check_1_1_14() {
  local id="1.1.14"
  local desc="Ensure auditing is configured for containerd files and directories - /usr/bin/containerd (Automated)"
  local remediation="Install auditd. Add -w /usr/bin/containerd -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="/usr/bin/containerd"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "        * File not found"
  logcheckresult "NOTE" "File not found"
}

check_1_1_15() {
  local id="1.1.15"
  local desc="Ensure auditing is configured for containerd files and directories - /usr/bin/containerd-shim (Automated)"
  local remediation="Install auditd. Add -w /usr/bin/containerd-shim -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="/usr/bin/containerd-shim"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "        * File not found"
  logcheckresult "NOTE" "File not found"
}

check_1_1_16() {
  local id="1.1.16"
  local desc="Ensure auditing is configured for containerd files and directories - /usr/bin/containerd-shim-runc-v1 (Automated)"
  local remediation="Install auditd. Add -w /usr/bin/containerd-shim-runc-v1 -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="/usr/bin/containerd-shim-runc-v1"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "        * File not found"
  logcheckresult "NOTE" "File not found"
}

check_1_1_17() {
  local id="1.1.17"
  local desc="Ensure auditing is configured for containerd files and directories - /usr/bin/containerd-shim-runc-v2 (Automated)"
  local remediation="Install auditd. Add -w /usr/bin/containerd-shim-runc-v2 -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="/usr/bin/containerd-shim-runc-v2"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "        * File not found"
  logcheckresult "NOTE" "File not found"
}

check_1_1_18() {
  local id="1.1.18"
  local desc="Ensure auditing is configured for containerd files and directories - /usr/bin/runc (Automated)"
  local remediation="Install auditd. Add -w /usr/bin/runc -k containerd to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart."
  local remediationImpact="Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="/usr/bin/runc"
  if [ -f "$file" ]; then
    if command -v auditctl >/dev/null 2>&1; then
      if auditctl -l | grep $file >/dev/null 2>&1; then
        pass -s "$check"
        logcheckresult "PASS"
        return
      fi
      warn -c "$check"
      logcheckresult "WARN"
      return
    fi
    if grep -s "$file" "$auditrules" | grep "^[^#;]" 2>/dev/null 1>&2; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  note -c "$check"
  note "        * File not found"
  logcheckresult "NOTE" "File not found"
}

check_1_2() {
  local id="1.2"
  local desc="General Configuration"
  local check="$id - $desc"
  info "$check"
}

check_1_2_1() {
  local id="1.2.1"
  local desc="Ensure the container host has been Hardened (Manual - not scored)"
  local remediation="You may consider various Security Benchmarks for your container host."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  note -c "$check"
  logcheckresult "INFO"
}

check_1_2_2() {
  local id="1.2.2"
  local desc="Ensure that the version of containerd is up to date (Manual - not scored)"
  local remediation="You should monitor versions of containerd releases and make sure your software is updated as required."
  local remediationImpact="You should perform a risk assessment regarding containerd version updates and review how they may impact your operations."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  containerd_version=$(containerd --version | awk '$1=="containerd" {print $3}')
 
  note -c "$check"
  note "       * Using $containerd_version. Please verify if that is up-to-date"
  logcheckresult "INFO" "Using $containerd_version"
}

check_1_end() {
  endsectionjson
}