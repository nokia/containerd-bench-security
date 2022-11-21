#!/bin/bash

check_2() {
  logit ""
  local id="2"
  local desc="containerd daemon configuration"
  checkHeader="$id - $desc"
  info "$checkHeader"
  startsectionjson "$id" "$desc"
}

#check_2_1() {
#  local id="2.1"
#  local desc="Run the Docker daemon as a non-root user, if possible (Manual)"
#  Testcase not applicable for containerd
#}

#check_2_2() {
#  local id="2.2"
#  local desc="Ensure network traffic is restricted between containers on the default bridge (Automated)"
#  Testcase not applicable for containerd
#}

check_2_3() {
  local id="2.3"
  local desc="Ensure the logging level is set to 'info' (Automated)"
  #local remediation="Ensure that the containerd configuration file has the following configuration included log-level: info."
  #local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  if get_containerd_configuration_file_args 'debug' >/dev/null 2>&1; then
    if get_containerd_configuration_file_args 'level = ' | grep info >/dev/null 2>&1; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    if [ -z "$(get_containerd_configuration_file_args 'level = ')" ]; then
      pass -s "$check"
      logcheckresult "PASS"
      return
    fi
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  
  pass -s "$check"
  logcheckresult "PASS"
}

#check_2_4() {
#  local id="2.4"
#  local desc="Ensure Docker is allowed to make changes to iptables (Automated)"
#  Testcase not applicable for containerd
#}

check_2_5() {
  local id="2.5"
  local desc="Ensure insecure registries are not used (Automated)"
  local remediation="You should ensure that no insecure registries are in use."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"
 
  get_containerd_configuration_file
  
  if cat "$CONFIG_FILE" | grep -E 'insecure_skip_verify.*true' >/dev/null 2>&1; then
      warn -c "$check"
      logcheckresult "WARN"
      return
  fi
  pass -s "$check"
  logcheckresult "PASS"
  
}

check_2_6() {
  local id="2.6"
  local desc="Ensure aufs storage driver is not used (Automated)"
  local remediation="Do not start Docker daemon as using dockerd --storage-driver aufs option."
  local remediationImpact="aufs is the only storage driver that allows containers to share executable and shared  library memory. Its use should be reviewed in line with your organization's security policy."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  if docker info 2>/dev/null | grep -e "^\sStorage Driver:\s*aufs\s*$" >/dev/null 2>&1; then
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  pass -s "$check"
  logcheckresult "PASS"
}

#check_2_7() {
#  local id="2.7"
#  local desc="Ensure TLS authentication for Docker daemon is configured (Automated)"
#  Testcase not applicable for containerd
#}

check_2_8() {
  local id="2.8"
  local desc="Ensure the default ulimit is configured appropriately (Manual) - to be checked for containerd"
  #local remediation="Run Docker in daemon mode and pass --default-ulimit as option with respective ulimits as appropriate in your environment and in line with your security policy. Example: dockerd --default-ulimit nproc=1024:2048 --default-ulimit nofile=100:200"
  #local remediationImpact="If ulimits are set incorrectly this could cause issues with system resources, possibly causing a denial of service condition."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  #if get_docker_configuration_file_args 'default-ulimit' | grep -v '{}' >/dev/null 2>&1; then
  #  pass -c "$check"
  #  logcheckresult "PASS"
  #  return
  #fi
  #if get_docker_effective_command_line_args '--default-ulimit' | grep "default-ulimit" >/dev/null 2>&1; then
  #  pass -c "$check"
  #  logcheckresult "PASS"
  #  return
  #fi
  info "$check"
  #info "     * Default ulimit doesn't appear to be set"
  #logcheckresult "INFO" "Default ulimit doesn't appear to be set"
  info "      * INFO -- Testcase to be checked for containerd"
  logcheckresult "INFO" "CHECK -- Testcase to be checked for containerd"
}

check_2_9() {
  local id="2.9"
  local desc="Enable user namespace support (Manual) - to be checked for containerd"
  local remediation="Please consult the Docker documentation for various ways in which this can be configured depending upon your requirements. The high-level steps are: Ensure that the files /etc/subuid and /etc/subgid exist. Start the docker daemon with --userns-remap flag."
  local remediationImpact="User namespace remapping is incompatible with a number of Docker features and also currently breaks some of its functionalities."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  #if get_docker_configuration_file_args 'userns-remap' | grep -v '""'; then
  #  pass -s "$check"
  #  logcheckresult "PASS"
  #  return
  #fi
  #if get_docker_effective_command_line_args '--userns-remap' | grep "userns-remap" >/dev/null 2>&1; then
  #  pass -s "$check"
  #  logcheckresult "PASS"
  #  return
  #fi
  #warn -c "$check"
  #logcheckresult "WARN"
  info "$check"
  info "      * INFO -- Testcase to be checked for containerd"
  logcheckresult "INFO" "CHECK -- Testcase to be checked for containerd"
}

check_2_10() {
  local id="2.10"
  local desc="Ensure the default cgroup usage has been confirmed (Automated)"
  local remediation="The default setting is in line with good security practice and can be left in situ."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  if get_containerd_configuration_file_args 'SystemdCgroup: true' | grep -v ''; then
    warn -c "$check"
    info "     * Confirm cgroup usage"
    logcheckresult "WARN" "Confirm cgroup usage"
    return
  fi

  pass -s "$check"
  logcheckresult "PASS"
}

#check_2_11() {
#  local id="2.11"
#  local desc="Ensure base device size is not changed until needed (Automated)"
#  Testcase not applicable for containerd
#}

#check_2_12() {
#  local id="2.12"
#  local desc="Ensure that authorization for Docker client commands is enabled (Automated)"
#  Testcase not applicable for containerd
#}

check_2_13() {
  local id="2.13"
  local desc="Ensure centralized and remote logging is configured (Automated)"
  local remediation="Set up the desired log driver following its documentation. Start containerd using that logging driver."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"
  
  get_containerd_configuration_file


  if cat "$CONFIG_FILE" | grep 'json-file' >/dev/null 2>&1; then
    warn -c "$check"
    logcheckresult "WARN"
    return
  fi
  pass -s "$check"
  logcheckresult "PASS"
}

#check_2_14() {
#  local id="2.14"
#  local desc="Ensure containers are restricted from acquiring new privileges (Manual)  - to be checked for containerd"
#  Testcase not applicable for containerd
#}

#check_2_15() {
#  local id="2.15"
#  local desc="Ensure live restore is enabled (Manual - to be checked for containerd)"
#  Testcase not applicable for containerd
#}

#check_2_16() {
#  local id="2.16"
#  local desc="Ensure Userland Proxy is Disabled (Automated)"
#  Testcase not applicable for containerd
#}

#check_2_17() {
#  local id="2.17"
#  local desc="Ensure that a daemon-wide custom seccomp profile is applied if appropriate (Manual) - to be checked for containerd"
#  Testcase not applicable for containerd
#}

#check_2_18() {
#  local id="2.18"
#  local desc="Ensure that experimental features are not implemented in production (Automated)"
#  Testcase not applicable for containerd
#}

check_2_end() {
  endsectionjson
}
