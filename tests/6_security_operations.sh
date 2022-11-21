#!/bin/bash
# Copyright 2022 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0


check_6() {
  logit ""
  local id="6"
  local desc="Security Operations"
  checkHeader="$id - $desc"
  info "$checkHeader"
  startsectionjson "$id" "$desc"
}

check_6_1() {
  local id="6.1"
  local desc="Ensure that image sprawl is avoided (Manual - not scored)"
  local remediation="You should keep only the images that you actually need and establish a workflow to remove old or stale images from the host. Additionally, you should use features such as pull-by-digest to get specific images from the registry."
  local remediationImpact="docker system prune -a removes all exited containers as well as all images and volumes that are not referenced by running containers, including for UCP and DTR."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  nr_images=$(echo "$images" | sort -u | wc -l)
  nr_active_images=$(crictl ps -a | sed '1d' | grep -v "$benchimagecont" | awk '{print $1 " " $2}' | sort -k 2 -u | wc -l)

  note -c "$check"
  note "     * There are currently: $nr_images images"

  if [ "$nr_active_images" -lt "$((nr_images / 2))" ]; then
    note "     * Only $nr_active_images out of $nr_images are in use"
  fi
  logcheckresult "INFO" "$nr_active_images active/$nr_images in use"
}

check_6_2() {
  local id="6.2"
  local desc="Ensure that container sprawl is avoided (Manual - not scored)"
  local remediation="You should periodically check your container inventory on each host and clean up containers which are not in active use"
  local remediationImpact="You should retain containers that are actively in use, and delete ones which are no longer needed."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  total_containers=$(crictl ps -a | wc -l)
  running_containers=$(crictl ps  | wc -l )
  diff="$((total_containers - running_containers))"
  note -c "$check"
  if [ "$diff" -gt 25 ]; then
    note "     * There are currently a total of $total_containers containers, with only $running_containers of them currently running"
  else
    note "     * There are currently a total of $total_containers containers, with $running_containers of them currently running"
  fi
  logcheckresult "INFO" "$total_containers total/$running_containers running"
}

check_6_end() {
  endsectionjson
}
