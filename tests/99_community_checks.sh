#!/bin/bash
# Copyright 2022 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0


check_c() {
  logit ""
  local id="99"
  local desc="Community contributed checks"
  checkHeader="$id - $desc"
  info "$checkHeader"
  startsectionjson "$id" "$desc"
}

check_c_3_7() {
  local id="Nokia 3.7"
  local desc="Ensure that Nokia BCMT registry certificate file ownership is set to root:root (Automated) "
  local remediation="You should run the following command: chown root:root /opt/bcmt/config/bcmt-registry/certs/ca.pem. This would set the individual ownership and group ownership for the registry certificate files to root."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"
  
  get_containerd_configuration_file
  
  bcmt_pem_file=$(cat "$CONFIG_FILE" | awk 'BEGIN{i=0;} /\[plugins.*.\"bcmt-registry\".tls\]/ {i=1;} {if(i==1) print}' | awk '$1=="ca_file"{print $3;exit;}' | sed -e 's/"//g' -e "s/'//g")
  if [ ! -z "$bcmt_pem_file" ]; then
    if [ "$(stat -c %u "$bcmt_pem_file")" -ne 0 ]; then
       warn -s "$check"
       warn "     * Wrong ownership for $bcmt_pem_file"
       logcheckresult "WARN" "Wrong ownership for $bcmt_pem_file"
       return
    fi
	pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  info -c "$check"
  info "     * Directory not found"
  logcheckresult "INFO" "Directory not found"
}


check_c_end() {
  endsectionjson
}
