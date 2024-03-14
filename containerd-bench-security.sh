#!/bin/bash
# Copyright 2022 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

# ----------------------------------------------------------------------------------------------------------
# containerd Bench for Security
#
# based on Docker Bench for Security 1.3.6 -- Docker, Inc. (c) 2015-2021
#
# Checks for dozens of common best-practices around deploying containerd managed containers in production.
# ----------------------------------------------------------------------------------------------------------

version='0.0.1'

# Load dependencies
. ./functions/functions_lib.sh
. ./functions/helper_lib.sh

# Setup the paths
this_path=$(abspath "$0")       ## Path of this file including filename
myname=$(basename "${this_path%.*}")     ## file name of this script.

readonly version
readonly this_path
readonly myname

export PATH="$PATH:/bin:/sbin:/usr/bin:/usr/local/bin:/usr/sbin/"

# Check for required program(s)
req_programs 'awk grep stat tee tail wc xargs truncate sed crictl'

# set up containerd runtime endpoint
get_containerd_configuration_file
# Option 1: Retrieve socket from config file if available
socket=$(cat "$CONFIG_FILE" | grep "\[grpc\]" -A10 | sed 's/.*://g' | tr -d '" ' | grep '^address'| awk -F= '{print $2}')
# Option 2: If config file doesn't provide the socket, retrieve it from containerd config dump
if [ -z "$socket" ]; then
        socket=$(containerd config dump | grep -i 'address' | grep sock | awk -F' ' '{print $3}' | tr -d '"')
else
  printf "Can't retrieve containerd's socket address\n"
  exit 1
fi

export CONTAINER_RUNTIME_ENDPOINT="unix://$socket"

# Ensure crictl works
if ! crictl ps -q >/dev/null 2>&1; then
  printf "Something is not right... (does crictl ps work?)\n"
  exit 1
fi

usage () {
  cat <<EOF
containerd Bench for Security - Nokia $(date +"%Y")

Based on Docker Bench for Security 1.3.6 -- Docker, Inc. (c) 2015-2021

Checks for dozens of common best-practices around deploying containerd managed containers in production.
Based on the CIS Docker Benchmark 1.3.1.

Usage: ${myname}.sh [OPTIONS]

Example:
  - Only run check "2.2 - Ensure the logging level is set to 'info'":
      sh containerd-bench-security.sh -c check_2_2
  - Run all available checks except the host_configuration group and "2.8 - Enable user namespace support":
      sh containerd-bench-security.sh -e host_configuration,check_2_8
  - Run just the container_images checks except "4.4 - Ensure images are scanned and rebuilt to include security patches (Manual - not scored)":
      sh containerd-bench-security.sh -c container_images -e check_4_4

Options:
  -b           optional  Do not print colors
  -h           optional  Print this help message
  -l FILE      optional  Log output in FILE, inside container if run using containerd
  -u USERS     optional  Comma delimited list of trusted containerd user(s)
  -c CHECK     optional  Comma delimited list of specific check(s) id
  -e CHECK     optional  Comma delimited list of specific check(s) id to exclude
  -i INCLUDE   optional  Comma delimited list of patterns within a container or image name to check
  -x EXCLUDE   optional  Comma delimited list of patterns within a container or image name to exclude from check
  -n LIMIT     optional  In JSON output, when reporting lists of items (containers, images, etc.), limit the number of reported items to LIMIT. Default 0 (no limit).
  -p PRINT     optional  Print remediation measures. Default: Don't print remediation measures.

Complete list of checks: <https://github.com/bekefi-laszlo/containerd-bench-security/blob/master/tests/>
Full documentation: <https://github.com/bekefi-laszlo/containerd-bench-security>
Released under the Apache-2.0 License.
EOF
}
 
# Default values
if [ ! -d log ]; then
  mkdir log
fi

logger="log/${myname}.log"
limit=0
printremediation="0"
globalRemediation=""

# Get the flags
# If you add an option here, please
# remember to update usage() above.
while getopts bhl:u:c:e:i:x:t:n:p args
do
  case $args in
  b) nocolor="nocolor";;
  h) usage; exit 0 ;;
  l) logger="$OPTARG" ;;
  u) containerdtrustusers="$OPTARG" ;;
  c) check="$OPTARG" ;;
  e) checkexclude="$OPTARG" ;;
  i) include="$OPTARG" ;;
  x) exclude="$OPTARG" ;;
  n) limit="$OPTARG" ;;
  p) printremediation="1" ;;
  *) usage; exit 1 ;;
  esac
done

# Load output formating
. ./functions/output_lib.sh

yell_info

# Warn if not root
if [ "$(id -u)" != "0" ]; then
  warn "$(yell 'Some tests might require root to run')\n"
  sleep 3
fi

# Total Score
# totalChecks = total number of testcases
# scoredChecks = total number of testcases (including manual ones) which are to be taken into account for score calculations
# currentScore = nr of automated passed testcases

totalChecks=0
scoredChecks=0
currentScore=0

logit "Initializing $(date +%Y-%m-%dT%H:%M:%S%:z)\n"
beginjson "$version" "$(date +%s)"

# Load all the tests from tests/ and run them
main () {
  logit "\n${bldylw}Section A - Check results${txtrst}"

  # Get configuration location
  get_containerd_configuration_file

  # If there is a container with label containerd.bench.security, memorize it:
  benchcont="nil"
  benchimagecont="nil"
  for c in $(crictl ps | sed '1d' | awk '{print $1}'); do
    if crictl inspect -o yaml "$c" | \
     grep -e 'containerd.bench.security' >/dev/null 2>&1; then
      benchcont="$c"
      benchimagecont=$(crictl ps | sed '1d' | grep "$c" | awk '{print $2}')
    fi
  done

  if [ -n "$include" ]; then
    pattern=$(echo "$include" | sed 's/,/|/g')
    containers=$(crictl ps | sed '1d' | awk '{print $1}' | grep -v "$benchcont" | grep -E "$pattern")
    images=$(crictl images ls | sed '1d' | grep -E "$pattern" | awk '{print $3}' | grep -v "$benchimagecont")
  elif [ -n "$exclude" ]; then
    pattern=$(echo "$exclude" | sed 's/,/|/g')
    containers=$(crictl ps | sed '1d' | awk '{print $1}' | grep -v "$benchcont" | grep -Ev "$pattern")
    images=$(crictl images ls | sed '1d' | grep -Ev "$pattern" | awk '{print $3}' | grep -v "$benchimagecont")
  else
    containers=$(crictl ps | sed '1d' | awk '{print $1}' | grep -v "$benchcont")
    images=$(crictl images ls | sed '1d' | grep -v "$benchimagecont" | awk '{print $3}')
  fi

  for test in tests/*.sh; do
    . ./"$test"
  done

  if [ -z "$check" ] && [ ! "$checkexclude" ]; then
    # No options just run
    all
  elif [ -z "$check" ]; then
    # No check defined but excludes defined set to calls in cis() function
    check=$(sed -ne "/cis() {/,/}/{/{/d; /}/d; p}" functions/functions_lib.sh)
  fi

  for c in $(echo "$check" | sed "s/,/ /g"); do
    if ! command -v "$c" 2>/dev/null 1>&2; then
      echo "Check \"$c\" doesn't seem to exist."
      continue
    fi
    if [ -z "$checkexclude" ]; then
      # No excludes just run the checks specified
      "$c"
    else
      # Exludes specified and check exists
      checkexcluded="$(echo ",$checkexclude" | sed -e 's/^/\^/g' -e 's/,/\$|/g' -e 's/$/\$/g')"

      if echo "$c" | grep -E "$checkexcluded" 2>/dev/null 1>&2; then
        # Excluded
        continue
      elif echo "$c" | grep -vE 'check_[0-9]|check_[a-z]' 2>/dev/null 1>&2; then
        # Function not a check, fill loop_checks with all check from function
        loop_checks="$(sed -ne "/$c() {/,/}/{/{/d; /}/d; p}" functions/functions_lib.sh)"
      else
        # Just one check
        loop_checks="$c"
      fi

      for lc in $loop_checks; do
        if echo "$lc" | grep -vE "$checkexcluded" 2>/dev/null 1>&2; then
          # Not excluded
          "$lc"
        fi
      done
    fi
  done

  if [ -n "${globalRemediation}" ] && [ "$printremediation" = "1" ]; then
    logit "\n\n${bldylw}Section B - Remediation measures${txtrst}"
    logit "${globalRemediation}"
  fi

  logit "\n\n${bldylw}Section C - Score${txtrst}\n"
  info "Checks: $totalChecks"
  info "Scored checks: $scoredChecks"
  info "Score: $currentScore\n"

  endjson "$totalChecks" "$scoredChecks" "$currentScore" "$(date +%s)"
}

main "$@"
