#!/bin/bash
# Copyright 2022 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0


# Returns the absolute path of a given string
abspath () { case "$1" in /*)printf "%s\n" "$1";; *)printf "%s\n" "$PWD/$1";; esac; }

# Audit rules default path
auditrules="/etc/audit/audit.rules"

# Check for required program(s)
req_programs() {
  for p in $1; do
    command -v "$p" >/dev/null 2>&1 || { printf "Required program not found: %s\n" "$p"; exit 1; }
  done
  if command -v ss >/dev/null 2>&1; then
    netbin=ss
    return
  fi
  if command -v netstat >/dev/null 2>&1; then
    netbin=netstat
    return
  fi
  echo "ss or netstat command not found."
  exit 1
}


# Extracts commandline args from the newest running processes named like the first parameter
get_command_line_args() {
  PROC="$1"
  
  ARGS=""
  ARGS=$(pgrep -a "$PROC")
}

# Extract the cumulative command line arguments for the containerd daemon
#
# If specified multiple times, all matches are returned.
# Accounts for long and short variants, call with short option.
# Does not account for option defaults or implicit options.
get_containerd_cumulative_command_line_args() {
  OPTION="$1"

  get_command_line_args "containerd" 

  echo $ARGS |
  # normalize known long options to their short versions
  sed \
    -e 's/\-\-/\-/g' \
    -e 's/\-config/\-c/g' \
    -e 's/\-log-level/\-l/g' \
    -e 's/\-address/\-a/g' \
    -e 's/\-version/\-v/g' \
	-e 's/\-namespace/\-n/g' \
	-e 's/\-id/\-i/g' \
    |
    # normalize parameters separated by space(s) to -O=VALUE
    sed \
      -e 's/\-\([clavni]\)[= ]\([^- ][^ ]\)/-\1=\2/g' \
      |
    # get the last interesting option
    tr ' ' "\n" |
    grep "^${OPTION}" |
    # normalize quoting of values
    sed \
      -e 's/"//g' \
      -e "s/'//g" |
	# remove duplicates
	sort -u
}

# Extract the effective command line arguments for the containerd daemon
#
# Accounts for multiple specifications, takes the last option.
# Accounts for long and short variants, call with short option
# Does not account for option default or implicit options.
get_containerd_effective_command_line_args() {
  OPTION="$1"
  get_containerd_cumulative_command_line_args "$OPTION" | tail -n1
}

get_containerd_configuration_file() {
  FILE="$(get_containerd_effective_command_line_args '-c' | \
    sed 's/.*=//g')"
  echo $FILE
  if [ -f "$FILE" ]; then
    CONFIG_FILE="$FILE"
    return
  fi
  if [ -f '/etc/containerd/config.toml' ]; then
    CONFIG_FILE='/etc/containerd/config.toml'
    return
  fi
  CONFIG_FILE='/dev/null'
}

get_containerd_configuration_file_args() {
  OPTION="$1"

  get_containerd_configuration_file

  grep "$OPTION" "$CONFIG_FILE" | sed 's/.*://g' | tr -d '" ',
}

get_service_file() {
  SERVICE="$1"

  if [ -f "/etc/systemd/system/$SERVICE" ]; then
    echo "/etc/systemd/system/$SERVICE"
    return
  fi
  if [ -f "/lib/systemd/system/$SERVICE" ]; then
    echo "/lib/systemd/system/$SERVICE"
    return
  fi
  if [ -f "/run/containerd/$SERVICE" ]; then
    echo "/run/containerd/$SERVICE"
    return
  fi
  if systemctl show -p FragmentPath "$SERVICE" 2> /dev/null 1>&2; then
    systemctl show -p FragmentPath "$SERVICE" | sed 's/.*=//'
    return
  fi
  echo "/usr/lib/systemd/system/$SERVICE"
}

# retrieve command for package manager
get_list_cmd() {
  distro="${1}"

  case "$distro" in
    fedora|rhel|rocky)
      echo -n "rpm -qa"
      return
      ;;
    debian|ubuntu)
      echo -n "apt list --installed"
      return
      ;;
    alpine)
      echo -n "apk info"
      return
      ;;
    centos)
      echo -n "yum list --installed"
      return
      ;;
    *)
      echo -n "rpm -qa"
      return
      ;;
  esac
}

yell_info() {
yell "# ----------------------------------------------------------------------------------------------------------
# containerd Bench for Security -- v0.1 release
#
# (c) 2022 Nokia
# Licensed under the Apache License 2.0
# created by: Laszlo Bekefi  e-mail: laszlo.bekefi@nokia.com 
#
# based on Docker Bench for Security 1.3.6 -- Docker, Inc. (c) 2015-2021
#
# Checks for dozens of common best-practices around deploying containerd managed containers in production.
# ----------------------------------------------------------------------------------------------------------"
}
