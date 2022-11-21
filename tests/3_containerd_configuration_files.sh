#!/bin/bash
# Copyright 2022 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0


check_3() {
  logit ""
  local id="3"
  local desc="containerd daemon configuration files"
  checkHeader="$id - $desc"
  info "$checkHeader"
  startsectionjson "$id" "$desc"
}

check_3_1() {
  local id="3.1"
  local desc="Ensure that the containerd.service file ownership is set to root:root (Automated)"
  local remediation="Find out the file location: systemctl show -p FragmentPath containerd.service. If the file does not exist, this recommendation is not applicable. If the file does exist, you should run the command chown root:root <path>, in order to set the ownership and group ownership for the file to root."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file=$(get_service_file containerd.service)
  if [ -f "$file" ]; then
    if [ "$(stat -c %u%g "$file")" -eq 00 ]; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    warn "     * Wrong ownership for $file"
    logcheckresult "WARN" "Wrong ownership for $file"
    return
  fi
  note -c "$check"
  note "     * File not found"
  logcheckresult "NOTE" "File not found"
}

check_3_2() {
  local id="3.2"
  local desc="Ensure that containerd.service file permissions are appropriately set (Automated)"
  local remediation="Find out the file location: systemctl show -p FragmentPath containerd.service. If the file does not exist, this recommendation is not applicable. If the file exists, run the command chmod 644 <path> to set the file permissions to 644."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file=$(get_service_file containerd.service)
  if [ -f "$file" ]; then
    if [ "$(stat -c %a "$file")" -le 644 ]; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    warn "     * Wrong permissions for $file"
    logcheckresult "WARN" "Wrong permissions for $file"
    return
  fi
  note -c "$check"
  note "     * File not found"
  logcheckresult "NOTE" "File not found"
}

#check_3_3() {
#  local id="3.3"
#  local desc="Ensure that docker.socket file ownership is set to root:root (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_4() {
#  local id="3.4"
#  local desc="Ensure that docker.socket file permissions are set to 644 or more restrictive (Automated)"
#  Testcase not applicable for containerd
#}

check_3_5() {
  local id="3.5"
  local desc="Ensure that the /etc/containerd directory ownership is set to root:root (Automated)"
  #local remediation="You should run the following command: chown root:root /etc/containerd. This sets the ownership and group ownership for the directory to root."
  #local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  directory="/etc/containerd"
  if [ -d "$directory" ]; then
    if [ "$(stat -c %u%g $directory)" -eq 00 ]; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    warn "     * Wrong ownership for $directory"
    logcheckresult "WARN" "Wrong ownership for $directory"
    return
  fi
  note -c "$check"
  note "     * Directory not found"
  logcheckresult "NOTE" "Directory not found"
}

check_3_6() {
  local id="3.6"
  local desc="Ensure that /etc/containerd directory permissions are set to 755 or more restrictively (Automated)"
  local remediation="You should run the following command: chmod 755 /etc/containerd. This sets the permissions for the directory to 755."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  directory="/etc/containerd"
  if [ -d "$directory" ]; then
    if [ "$(stat -c %a $directory)" -le 755 ]; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    warn "     * Wrong permissions for $directory"
    logcheckresult "WARN" "Wrong permissions for $directory"
    return
  fi
  note -c "$check"
  note "     * Directory not found"
  logcheckresult "NOTE" "Directory not found"
}

check_3_7() {
  local id="3.7"
  local desc="Ensure that registry certificate file ownership is set to root:root (Automated)"
  local remediation="You should run the following command: chown root:root <registry-directory>/*. This would set the individual ownership and group ownership for the registry certificate files to root."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"
  
  get_containerd_configuration_file
  directory=$(cat "$CONFIG_FILE" | awk 'BEGIN{i=0;} /\[plugins.*.registry\]/ {i=1;} {if(i==1) print}' | awk '$1=="config_path"{print $3;exit;}')

  if [ -d "$directory" ]; then
    fail=0
    owners=$(find "$directory" -type f \( -name "*.crt" -o -name "*.toml" \)) 
    for p in $owners; do
      if [ "$(stat -c %u "$p")" -ne 0 ]; then
        fail=1
      fi
    done
    if [ $fail -eq 1 ]; then
      warn -c "$check"
      warn "     * Wrong ownership for $directory"
      logcheckresult "WARN" "Wrong ownership for $directory"
      return
    fi
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  
  note -c "$check"
  note "     * Directory not found"
  logcheckresult "NOTE" "Directory not found"
}

check_3_8() {
  local id="3.8"
  local desc="Ensure that registry certificate file permissions are set to 444 or more restrictively (Automated)"
  local remediation="You should run the following command: chmod 444 /etc/docker/certs.d/<registry-name>/*. This would set the permissions for the registry certificate files to 444."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  get_containerd_configuration_file
  directory=$(cat "$CONFIG_FILE" | awk 'BEGIN{i=0;} /\[plugins.*.registry\]/ {i=1;} {if(i==1) print}' | awk '$1=="config_path"{print $3;exit;}')

  if [ -d "$directory" ]; then
    fail=0
    perms=$(find "$directory" -type f \( -name "*.crt" -o -name "*.toml" \)) 
    for p in $perms; do
      if [ "$(stat -c %a "$p")" -gt 444 ]; then
        fail=1
      fi
    done
    if [ $fail -eq 1 ]; then
      warn -c "$check"
      warn "     * Wrong permissions for $directory"
      logcheckresult "WARN" "Wrong permissions for $directory"
      return
    fi
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  note -c "$check"
  note "     * Directory not found"
  logcheckresult "NOTE" "Directory not found"
}

check_3_9() {
  local id="3.9"
  local desc="Ensure that TLS CA certificate file ownership is set to root:root (Automated) - to be checked for containerd"
  local remediation="You should run the following command: chown root:root <path to TLS CA certificate file>. This sets the individual ownership and group ownership for the TLS CA certificate file to root."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  tlscacert=$(get_containerd_effective_command_line_args '--tlscacert' | sed -n 's/.*tlscacert=\([^s]\)/\1/p' | sed 's/--/ --/g' | cut -d " " -f 1)
  if [ -n "$tlscacert" ]; then
    tlscacert=$(get_containerd_configuration_file_args 'tls_cert_file')
  fi
  if [ -f "$tlscacert" ]; then
    if [ "$(stat -c %u%g "$tlscacert")" -eq 00 ]; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    warn "     * Wrong ownership for $tlscacert"
    logcheckresult "WARN" "Wrong ownership for $tlscacert"
    return
  fi
  info "$check"
  info "     * No TLS CA certificate found, testcase to be checked for containerd"
  logcheckresult "INFO" "No TLS CA certificate found"
}

check_3_10() {
  local id="3.10"
  local desc="Ensure that TLS CA certificate file permissions are set to 444 or more restrictively (Automated) - to be checked for containerd"
  local remediation="You should run the following command: chmod 444 <path to TLS CA certificate file>. This sets the file permissions on the TLS CA file to 444."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  tlscacert=$(get_containerd_effective_command_line_args '--tlscacert' | sed -n 's/.*tlscacert=\([^s]\)/\1/p' | sed 's/--/ --/g' | cut -d " " -f 1)
  if [ -n "$tlscacert" ]; then
    tlscacert=$(get_containerd_configuration_file_args 'tlscacert')
  fi
  if [ -f "$tlscacert" ]; then
    if [ "$(stat -c %a "$tlscacert")" -le 444 ]; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    warn "      * Wrong permissions for $tlscacert"
    logcheckresult "WARN" "Wrong permissions for $tlscacert"
    return
  fi
  info "$check"
  info "      * No TLS CA certificate found, testcase to be checked for containerd"
  logcheckresult "INFO" "No TLS CA certificate found"
}

#check_3_11() {
#  local id="3.11"
#  local desc="Ensure that Docker server certificate file ownership is set to root:root (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_12() {
#  local id="3.12"
#  local desc="Ensure that the Docker server certificate file permissions are set to 444 or more restrictively (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_13() {
#  local id="3.13"
#  local desc="Ensure that the Docker server certificate key file ownership is set to root:root (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_14() {
#  local id="3.14"
#  local desc="Ensure that the Docker server certificate key file permissions are set to 400 (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_15() {
#  local id="3.15"
#  local desc="Ensure that the Docker socket file ownership is set to root:docker (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_16() {
#  local id="3.16"
#  local desc="Ensure that the Docker socket file permissions are set to 660 or more restrictively (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_17() {
#  local id="3.17"
#  local desc="Ensure that the daemon.json file ownership is set to root:root (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_18() {
#  local id="3.18"
#  local desc="Ensure that daemon.json file permissions are set to 644 or more restrictive (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_19() {
#  local id="3.19"
#  local desc="Ensure that the /etc/default/docker file ownership is set to root:root (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_20() {
#  local id="3.20"
#  local desc="Ensure that the /etc/sysconfig/docker file permissions are set to 644 or more restrictively (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_21() {
#  local id="3.21"
#  local desc="Ensure that the /etc/sysconfig/docker file ownership is set to root:root (Automated)"
#  Testcase not applicable for containerd
#}

#check_3_22() {
#  local id="3.22"
#  local desc="Ensure that the /etc/default/docker file permissions are set to 644 or more restrictively (Automated)"
#  Testcase not applicable for containerd
#}

check_3_23() {
  local id="3.23"
  local desc="Ensure that the Containerd socket file ownership is set to root:root (Automated)"
  local remediation="You should run the following command: chown root:root /run/containerd/containerd.sock. This sets the ownership and group ownership for the file to root."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="/run/containerd/containerd.sock"
  if [ "test -f $file" ]; then
    if [ "$(stat -c %U:%G $file)" = 'root:root' ]; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    warn "      * Wrong ownership for $file"
    logcheckresult "WARN" "Wrong ownership for $file"
    return
  fi
  note -c "$check"
  note "      * File not found"
  logcheckresult "NOTE" "File not found"
}

check_3_24() {
  local id="3.24"
  local desc="Ensure that the Containerd socket file permissions are set to 660 or more restrictively (Automated)"
  local remediation="You should run the following command: chmod 660 /run/containerd/containerd.sock. This sets the file permissions for this file to 660."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  file="/run/containerd/containerd.sock"
  if [ "test -f $file" ]; then
    if [ "$(stat -c %a $file)" -le 660 ]; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    warn "      * Wrong permissions for $file"
    logcheckresult "WARN" "Wrong permissions for $file"
    return
  fi
  note -c "$check"
  note "      * File not found"
  logcheckresult "NOTE" "File not found"
}

check_3_end() {
  endsectionjson
}
