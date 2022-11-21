#!/bin/bash

check_5() {
  logit ""
  local id="5"
  local desc="Container Runtime"
  checkHeader="$id - $desc"
  info "$checkHeader"
  startsectionjson "$id" "$desc"
}

check_running_containers() {
  # If containers is empty, there are no running containers
  if [ -z "$containers" ]; then
    info "  * No containers running, skipping Section 5"
    return
  fi
  # Make the loop separator be a new-line in POSIX compliant fashion
  set -f; IFS=$'
  '
}

check_5_1() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.1"
  local desc="Ensure that, if applicable, AppArmor Profile is not disabled (Automated)"
  local remediation="If AppArmor is applicable for your Linux OS, you should not disable it. "
  local remediationImpact="The container will have the security controls defined in the AppArmor profile. It should be noted that if the AppArmor profile is misconfigured, this may cause issues with the operation of the container."
  local check="$id - $desc"
  starttestjson "$id" "$desc"


  if ! [ -z $(get_containerd_configuration_file_args 'disable_apparmor=true') ]; then
      warn -c "$check"
      warn "     * AppArmor disabled in containerd config"
      logcheckresult "WARN" "AppArmor disabled"
      return
   fi
  pass -s "$check"
  logcheckresult "PASS"

}

check_5_2() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.2"
  local desc="Ensure that, if applicable, SELinux security options are set (Automated)"
  local remediation="Don't disable SELinux in containerd configuration."
  local remediationImpact="Any restrictions defined in the SELinux policy will be applied to your containers. It should be noted that if your SELinux policy is misconfigured, this may have an impact on the correct operation of the affected containers."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  if [ -z $(get_containerd_configuration_file_args 'enable_selinux=false') ]; then
    warn -c "$check"
    warn "     * SELinux is disabled in containerd configuration"
  fi
  pass -s "$check"
  logcheckresult "PASS"

}

check_5_3() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.3"
  local desc="Ensure that Linux kernel capabilities are restricted within containers (Automated)"
  local remediation="You could remove all the currently configured capabilities and then restore only the ones you specifically use."
  local remediationImpact="Restrictions on processes within a container are based on which Linux capabilities are in force. Removal of the NET_RAW capability prevents the container from creating raw sockets which is good security practice under most circumstances, but may affect some networking utilities."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  for c in $containers; do

	container_caps=$(crictl inspect -o json "$c" | awk '/"capabilities":/{flag=1;next}/}/{flag=0}flag')
    caps=$(echo "$container_caps"| tr "[:lower:]" "[:upper:]" | sed -r "s/BOUNDING|INHERITABLE|EFFECTIVE|PERMITTED|\s//g" | tr -d '":,[]\015' | sort -u | wc -l)


    if [ $caps ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "     * Capabilities added: $caps to $c"
        fail=1
        continue
      fi
      warn "     * Capabilities added: $caps to $c"
    fi
  done
  # We went through all the containers and found none with extra capabilities
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Capabilities added for containers"
}

check_5_4() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.4"
  local desc="Ensure that privileged containers are not used (Automated)"
  local remediation="You should not run containers with the --privileged flag."
  local remediationImpact="If you start a container without the --privileged flag, it will not have excessive default capabilities."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  privileged_containers=""
  for c in $containers; do
    if crictl inspect -o yaml "$c" 2>/dev/null | grep -i "privileged: true" 1>/dev/null; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "     * Container running in Privileged mode: $c"
        privileged_containers="$privileged_containers $c"
        fail=1
      else
        warn "     * Container running in Privileged mode: $c"
        privileged_containers="$privileged_containers $c"
      fi
    fi
  done
  # We went through all the containers and found no privileged containers
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers running in privileged mode" "$privileged_containers"
}

check_5_5() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.5"
  local desc="Ensure sensitive host system directories are not mounted on containers (Automated)"
  local remediation="You should not mount directories which are security sensitive on the host within containers, especially in read-write mode."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  # List of sensitive directories to test for. Script uses new-lines as a separator.
  # Note the lack of identation. It needs it for the substring comparison.
  sensitive_dirs='/
/boot
/dev
/etc
/lib
/proc
/sys
/usr'
  fail=0
  sensitive_mount_containers=""
  for c in $containers; do
	volumes=$(crictl inspect -o yaml "$c" | awk -F: '$1 ~ /destination/ {saved=$2} $0 ~ /- rw/ { gsub(/ /, "", saved);print saved}')
    # Go over each directory in sensitive dir and see if they exist in the volumes
    for v in $sensitive_dirs; do
      sensitive=0
      if echo "$volumes" | grep -e "{.*\s$v\s.*true\s.*}" 2>/tmp/null 1>&2; then
        sensitive=1
      fi
      if [ $sensitive -eq 1 ]; then
        # If it's the first container, fail the test
        if [ $fail -eq 0 ]; then
          warn -c "$check"
          warn "     * Sensitive directory $v mounted in: $c"
          sensitive_mount_containers="$sensitive_mount_containers $c:$v"
          fail=1
          continue
        fi
        warn "     * Sensitive directory $v mounted in: $c"
        sensitive_mount_containers="$sensitive_mount_containers $c:$v"
      fi
    done
  done
  # We went through all the containers and found none with sensitive mounts
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with sensitive directories mounted" "$sensitive_mount_containers"
}

check_5_6() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.6"
  local desc="Ensure sshd is not run within containers (Automated)"
  local remediation="Uninstall the SSH daemon from the container and use crictl exec to enter a container on the remote host."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  ssh_exec_containers=""
  printcheck=0
  for c in $containers; do

    processes=$(crictl exec -i -t "$c" ps -el 2>/dev/null | grep -c sshd | awk '{print $1}')
    if [ "$processes" -ge 1 ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "     * Container running sshd: $c"
        ssh_exec_containers="$ssh_exec_containers $c"
        fail=1
        printcheck=1
      else
        warn "     * Container running sshd: $c"
        ssh_exec_containers="$ssh_exec_containers $c"
      fi
    fi

    exec_check=$(crictl exec -i -t "$c" ps -el 2>/dev/null)
    if [ $? -eq 255 ]; then
        if [ $printcheck -eq 0 ]; then
          warn -c "$check"
          printcheck=1
        fi
      warn "     * SSH exec fails: $c"
      ssh_exec_containers="$ssh_exec_containers $c"
      fail=1
    fi

  done
  # We went through all the containers and found none with sshd
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with sshd exec failures" "$ssh_exec_containers"
}

check_5_7() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.7"
  local desc="Ensure privileged ports are not mapped within containers (Manual - not scored)"
  local remediation="You should not map container ports to privileged host ports when starting a container. You should also, ensure that there is no such container to host privileged port mapping declarations in the Dockerfile."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  note -c "$check"
  logcheckresult "NOTE"
}

check_5_8() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.8"
  local desc="Ensure that only needed ports are open on the container (Manual)"
  local remediation="You should ensure that the Dockerfile for each container image only exposes needed ports."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  note -c "$check"
  logcheckresult "NOTE"
}

check_5_9() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.9"
  local desc="Ensure that the host's network namespace is not shared (Manual - not scored)"
  #local remediation="You should not pass the --net=host option when starting any container."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  logcheckresult "WARN" "Containers running with networking mode 'host'"
  note -c "$check"
  logcheckresult "NOTE"
}

check_5_10() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.10"
  local desc="Ensure that the memory usage for containers is limited (Automated)"
  local remediation="You should run the container with only as much memory as it requires by using the --memory argument."
  local remediationImpact="If correct memory limits are not set on each container, one process can expand its usage and cause other containers to run out of resources."
  local check="$id - $desc"
  starttestjson "$id" "$desc"
  

  fail=0
  memlimit=0
  mem_unlimited_containers=""
  for c in $containers; do

    memory=$(crictl inspect "$c" | grep "memory_limit_in_bytes" | awk '{print substr($2, 1, length($2)-1)}')
    memory2=$(crictl inspect "$c" | grep "hugepage_limits" | awk '{print $2}')
	memory3=$(crictl inspect "$c" | grep "memory" | awk '{print $2}') 
	if [ "$memory1" != "" ] && [ "$memory2" = "[]" ] && [ "$memory3" = "{}" ]; then
	  memlimit=1
    fi

    if [ $memlimit -eq 1 ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "      * Container running without memory restrictions: $c"
        mem_unlimited_containers="$mem_unlimited_containers $c"
        fail=1
      else
        warn "      * Container running without memory restrictions: $c"
        mem_unlimited_containers="$mem_unlimited_containers $c"
      fi
      memlimit=0
    fi
  done
  # We went through all the containers and found no lack of Memory restrictions
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Container running without memory restrictions" "$mem_unlimited_containers"
}

check_5_11() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.11"
  local desc="Ensure that CPU priority is set appropriately on containers (Automated)"
  local remediation="You should manage the CPU runtime between your containers dependent on their priority within your organization. To do so start the container using the --cpu-shares argument."
  local remediationImpact="If you do not correctly assign CPU thresholds, the container process may run out of resources and become unresponsive. If CPU resources on the host are not constrainted, CPU shares do not place any restrictions on individual resources."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  cpu_unlimited_containers=""
  for c in $containers; do
    shares=$(crictl inspect "$c" | grep cpu -A5 | grep shares | awk '{print substr($2, 1, length($2)-1)}')
    if [ "$shares" = "0" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "      * Container running without CPU restrictions: $c"
        cpu_unlimited_containers="$cpu_unlimited_containers $c"
        fail=1
        continue
      fi
      warn "      * Container running without CPU restrictions: $c"
      cpu_unlimited_containers="$cpu_unlimited_containers $c"
    fi
  done
  # We went through all the containers and found no lack of CPUShare restrictions
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers running without CPU restrictions" "$cpu_unlimited_containers"
}

check_5_12() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.12"
  local desc="Ensure that the container's root filesystem is mounted as read only (Automated)"
  local remediation="You should add a --read-only flag at a container's runtime to enforce the container's root filesystem being mounted as read only."
  local remediationImpact="Enabling --read-only at container runtime may break some container OS packages if a data writing strategy is not defined. You should define what the container's data should and should not persist at runtime in order to decide which strategy to use."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  fsroot_mount_containers=""
  for c in $containers; do
   read_status=$(crictl inspect "$c" | grep rootfs -A2 | grep \"readonly\" | awk '{print $2}')

    if [ "$read_status" != "true" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "      * Container running with root FS mounted R/W: $c"
        fsroot_mount_containers="$fsroot_mount_containers $c"
        fail=1
        continue
      fi
      warn "      * Container running with root FS mounted R/W: $c"
      fsroot_mount_containers="$fsroot_mount_containers $c"
    fi
  done
  # We went through all the containers and found no R/W FS mounts
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers running with root FS mounted R/W" "$fsroot_mount_containers"
}

check_5_13() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.13"
  local desc="Ensure that incoming container traffic is bound to a specific host interface (Manual - not scored)"
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  note -c "$check"
  logcheckresult "NOTE"
}

check_5_14() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.14"
  local desc="Ensure that the 'on-failure' container restart policy is set (Manual - not scored)"
  local remediation="If you wish a container to be automatically restarted, a limit for restarts shall be set. (5 is the number of recommended restart attempts"
  local remediationImpact="If this option is set, a container will only attempt to restart itself 5 times."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  note -c "$check"
  logcheckresult "INFO"
}

check_5_15() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.15"
  local desc="Ensure that the host's process namespace is not shared (Manual)"
  local remediation="You should not start a container with the --pid=host argument."
  local remediationImpact="Container processes cannot see processes on the host system."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  pidns_shared_containers=""
  for c in $containers; do
    nspaces=$(crictl inspect -o json "$c" | awk '/"namespaces":/{flag=1;next}/]/{flag=0}flag')
	mode=$(echo "$nspaces" | awk '/pid/,/}/' | grep path | awk -F: '{print $2}')
	
    if [ "$mode" = "" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "      * Host PID namespace being shared with: $c"
        pidns_shared_containers="$pidns_shared_containers $c"
        fail=1
        continue
      fi
      warn "      * Host PID namespace being shared with: $c"
      pidns_shared_containers="$pidns_shared_containers $c"
    fi
  done
  # We went through all the containers and found none with PidMode as host
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers sharing host PID namespace" "$pidns_shared_containers"
}

check_5_16() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.16"
  local desc="Ensure that the host's IPC namespace is not shared (Automated)"
  local remediation="You should not start a container with the --ipc=host argument."
  local remediationImpact="Shared memory segments are used in order to accelerate interprocess communications, commonly in high-performance applications. If this type of application is containerized into multiple containers, you might need to share the IPC namespace of the containers in order to achieve high performance. Under these circumstances, you should still only share container specific IPC namespaces and not the host IPC namespace."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  ipcns_shared_containers=""
  for c in $containers; do
	nspaces=$(crictl inspect -o json "$c" | awk '/"namespaces":/{flag=1;next}/]/{flag=0}flag')
	mode=$(echo "$nspaces" | awk '/ipc/,/}/' | grep path | awk -F: '{print $2}')

    if [ "$mode" = "" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "      * Host IPC namespace being shared with: $c"
        ipcns_shared_containers="$ipcns_shared_containers $c"
        fail=1
        continue
      fi
      warn "      * Host IPC namespace being shared with: $c"
      ipcns_shared_containers="$ipcns_shared_containers $c"
    fi
  done
  # We went through all the containers and found none with IPCMode as host
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers sharing host IPC namespace" "$ipcns_shared_containers"
}

check_5_17() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.17"
  local desc="Ensure that host devices are not directly exposed to containers (Manual)"
  local remediation="You should not directly expose host devices to containers. If you do need to expose host devices to containers, you should use granular permissions as appropriate to your organization."
  local remediationImpact="You would not be able to use host devices directly within containers."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  hostdev_exposed_containers=""
  for c in $containers; do
	devices=$(crictl inspect "$c" | grep -i devices -A3 | grep \"allow\" | awk '{print substr($2, 1, length($2)-1)}')

    if [ "$devices" = "true" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        info -c "$check"
        info "      * Container has devices exposed directly: $c"
        hostdev_exposed_containers="$hostdev_exposed_containers $c"
        fail=1
        continue
      fi
      info "      * Container has devices exposed directly: $c"
      hostdev_exposed_containers="$hostdev_exposed_containers $c"
    fi
  done
  # We went through all the containers and found none with devices
  if [ $fail -eq 0 ]; then
    pass -c "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "INFO" "Containers with host devices exposed directly" "$hostdev_exposed_containers"
}

check_5_18() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.18"
  local desc="Ensure that the default ulimit is overwritten at runtime if needed (Manual - to be checked for containerd)"
  local remediation="You should only override the default ulimit settings if needed in a specific case."
  local remediationImpact="If ulimits are not set correctly, overutilization by individual containers could make the host system unusable."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  #fail=0
  #no_ulimit_containers=""
  #for c in $containers; do
  #  ulimits=$(docker inspect --format 'Ulimits={{ .HostConfig.Ulimits }}' "$c")

  #  if [ "$ulimits" = "Ulimits=" ] || [ "$ulimits" = "Ulimits=[]" ] || [ "$ulimits" = "Ulimits=<no value>" ]; then
  #    # If it's the first container, fail the test
  #    if [ $fail -eq 0 ]; then
  #      info -c "$check"
  #      info "      * Container no default ulimit override: $c"
  #      no_ulimit_containers="$no_ulimit_containers $c"
  #      fail=1
  #      continue
  #    fi
  #    info "      * Container no default ulimit override: $c"
  #    no_ulimit_containers="$no_ulimit_containers $c"
  #  fi
  #done
  # We went through all the containers and found none without Ulimits
  #if [ $fail -eq 0 ]; then
  #  pass -c "$check"
  #  logcheckresult "PASS"
  #  return
  #fi
  #logcheckresult "INFO" "Containers with no default ulimit override" "$no_ulimit_containers"
  
  info "$check"
  info "      * INFO -- Testcase to be checked for containerd"
  logcheckresult "INFO" "CHECK -- Testcase to be checked for containerd"
}

check_5_19() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.19"
  local desc="Ensure mount propagation mode is not set to shared (Automated)"
  local remediation="Do not mount volumes in shared mode propagation."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  mountprop_shared_containers=""
  for c in $containers; do
  	if crictl inspect "$c" | grep propagation | grep -i shared  2>/dev/null 1>&2; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "      * Mount propagation mode is shared: $c"
        mountprop_shared_containers="$mountprop_shared_containers $c"
        fail=1
        continue
      fi
      warn "      * Mount propagation mode is shared: $c"
      mountprop_shared_containers="$mountprop_shared_containers $c"
    fi
  done
  # We went through all the containers and found none with shared propagation mode
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with shared mount propagation" "$mountprop_shared_containers"
}

check_5_20() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.20"
  local desc="Ensure that the host's UTS namespace is not shared (Automated)"
  local remediation="You should not start a container with the --uts=host argument."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  utcns_shared_containers=""
  for c in $containers; do
  	nspaces=$(crictl inspect -o json "$c" | awk '/"namespaces":/{flag=1;next}/]/{flag=0}flag')
	mode=$(echo "$nspaces" | awk '/uts/,/}/' | grep path | awk -F: '{print $2}')

    if [ "$mode" = "" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "      * Host UTS namespace being shared with: $c"
        utcns_shared_containers="$utcns_shared_containers $c"
        fail=1
        continue
      fi
      warn "      * Host UTS namespace being shared with: $c"
      utcns_shared_containers="$utcns_shared_containers $c"
    fi
  done
  # We went through all the containers and found none with UTSMode as host
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers sharing host UTS namespace" "$utcns_shared_containers"
}

check_5_21() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.21"
  local desc="Ensurethe default seccomp profile is not Disabled (Automated)"
  local remediation="By default, seccomp profiles are enabled. You do not need to do anything unless you want to modify and use a modified seccomp profile."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  seccomp_disabled_containers=""
  for c in $containers; do
  	secopt=$(crictl inspect "$c" | grep -i SecurityOpt | awk '{print $2}')
	if [ "$secopt" = "null" ]; then  
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "      * Default seccomp profile disabled: $c"
        seccomp_disabled_containers="$seccomp_disabled_containers $c"
        fail=1
      else
        warn "      * Default seccomp profile disabled: $c"
        seccomp_disabled_containers="$seccomp_disabled_containers $c"
      fi
    fi
  done
  # We went through all the containers and found none with default secomp profile disabled
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with default seccomp profile disabled" "$seccomp_disabled_containers"
}

#check_5_22() {
#  if [ -z "$containers" ]; then
#    return
#  fi

#  local id="5.22"
#  local desc="Ensure that docker exec commands are not used with the privileged option (Manual)"
#  Testcase not applicable for containerd
#}

#check_5_23() {
#  if [ -z "$containers" ]; then
#    return
#  fi

#  local id="5.23"
#  local desc="Ensure that docker exec commands are not used with the user=root option (Manual)"
#  Testcase not applicable for containerd
#}}

check_5_24() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.24"
  local desc="Ensure that cgroup usage is confirmed (Manual - to be checked for containerd)"
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  #fail=0
  #unexpected_cgroup_containers=""
  #for c in $containers; do
  #  mode=$(docker inspect --format 'CgroupParent={{.HostConfig.CgroupParent }}x' "$c")

  #  if [ "$mode" != "CgroupParent=x" ]; then
      # If it's the first container, fail the test
  #    if [ $fail -eq 0 ]; then
  #      warn -c "$check"
  #      warn "      * Confirm cgroup usage: $c"
  #      unexpected_cgroup_containers="$unexpected_cgroup_containers $c"
  #      fail=1
  #      continue
  #    fi
  #    warn "      * Confirm cgroup usage: $c"
  #    unexpected_cgroup_containers="$unexpected_cgroup_containers $c"
  #  fi
  #done
  # We went through all the containers and found none with UTSMode as host
  #if [ $fail -eq 0 ]; then
  #  pass -s "$check"
  #  logcheckresult "PASS"
  #  return
  #fi
  #  logcheckresult "WARN" "Containers using unexpected cgroup" "$unexpected_cgroup_containers"
  info "$check"
  info "      * INFO -- Testcase to be checked for containerd"
  logcheckresult "INFO" "CHECK -- Testcase to be checked for containerd"

}

check_5_25() {
  if [ -z "$containers" ]; then
    return
  fi
  local id="5.25"
  local desc="Ensure that the container is restricted from acquiring additional privileges (Automated)"
  local remediation="You should ensure that in container config no-new-privileges ubuntu bash"
  local remediationImpact="The no_new_priv option prevents LSMs like SELinux from allowing processes to acquire new privileges."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  fail=0
  addprivs_containers=""
  for c in $containers; do
	prives1=$(crictl inspect "$c" | grep -i "noNewPrivileges" | awk '{print substr($2, 1, length($2)-1)}')
	prives2=$(crictl inspect "$c" | grep -i "no_new_privs" | awk '{print substr($2, 1, length($2)-1)}')

	if [ "$prives1" != "true" ] || [ "$prives2" != "true" ]; then

      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -c "$check"
        warn "      * Privileges not restricted: $c"
        addprivs_containers="$addprivs_containers $c"
        fail=1
        continue
      fi
      warn "      * Privileges not restricted: $c"
      addprivs_containers="$addprivs_containers $c"
    fi
  done
  # We went through all the containers and found none with capability to acquire additional privileges
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers without restricted privileges" "$addprivs_containers"
}

#check_5_26() {
#  if [ -z "$containers" ]; then
#    return
#  fi

#  local id="5.26"
#  local desc="Ensure that container health is checked at runtime (Automated)"
#  Testcase not applicable for containerd
#}

check_5_27() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.27"
  local desc="Ensure that commands always make use of the latest version of their image (Manual - not scored)"
  local remediation="You should use proper version pinning mechanisms (the <latest> tag which is assigned by default is still vulnerable to caching attacks) to avoid extracting cached older versions. Version pinning mechanisms should be used for base images, packages, and entire images. You can customize version pinning rules according to your requirements."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  note -c "$check"
  logcheckresult "INFO"
}

check_5_28() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.28"
  local desc="Ensure that the PIDs cgroup limit is used (Manual - te be checked for containerd)"
  local remediation="Use --pids-limit flag with an appropriate value when launching the container."
  local remediationImpact="Set the PIDs limit value as appropriate. Incorrect values might leave containers unusable."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  #fail=0
  #nopids_limit_containers=""
  #for c in $containers; do
  #  pidslimit="$(docker inspect --format '{{.HostConfig.PidsLimit }}' "$c")"

  #  if [ "$pidslimit" = "0" ] || [  "$pidslimit" = "<nil>" ] || [  "$pidslimit" = "-1" ]; then
      # If it's the first container, fail the test
  #    if [ $fail -eq 0 ]; then
  #      warn -c "$check"
  #      warn "      * PIDs limit not set: $c"
  #      nopids_limit_containers="$nopids_limit_containers $c"
  #      fail=1
  #      continue
  #    fi
  #    warn "      * PIDs limit not set: $c"
  #    nopids_limit_containers="$nopids_limit_containers $c"
  #  fi
  #done
  # We went through all the containers and found all with PIDs limit
  #if [ $fail -eq 0 ]; then
  #  pass -s "$check"
  #  logcheckresult "PASS"
  #  return
  #fi
  #logcheckresult "WARN" "Containers without PIDs cgroup limit" "$nopids_limit_containers"
  
  info "$check"
  info "      * INFO -- Testcase to be checked for containerd"
  logcheckresult "INFO" "CHECK -- Testcase to be checked for containerd"

}

#check_5_29() {
#  if [ -z "$containers" ]; then
#    return
#  fi

#  local id="5.29"
#  local desc="Ensure that Docker's default bridge 'docker0' is not used (Manual)"
#  Testcase not applicable for containerd
#}

check_5_30() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.30"
  local desc="Ensure that the host's user namespaces are not shared (Automated - to be checked for containerd)"
  local remediation="You should not share user namespaces between host and containers."
  local remediationImpact="None."
  local check="$id - $desc"
  starttestjson "$id" "$desc"

  #fail=0
  #hostns_shared_containers=""
  #for c in $containers; do
  #  if docker inspect --format '{{ .HostConfig.UsernsMode }}' "$c" 2>/dev/null | grep -i 'host' >/dev/null 2>&1; then
      # If it's the first container, fail the test
  #    if [ $fail -eq 0 ]; then
  #      warn -c "$check"
  #      warn "      * Namespace shared: $c"
  #      hostns_shared_containers="$hostns_shared_containers $c"
  #      fail=1
  #      continue
  #    fi
  #    warn "      * Namespace shared: $c"
  #    hostns_shared_containers="$hostns_shared_containers $c"
  #  fi
  #done
  # We went through all the containers and found none with host's user namespace shared
  #if [ $fail -eq 0 ]; then
  #  pass -s "$check"
  #  logcheckresult "PASS"
  #  return
  #fi
  #logcheckresult "WARN" "Containers sharing host user namespace" "$hostns_shared_containers"
  info "$check"
  info "      * INFO -- Testcase to be checked for containerd"
  logcheckresult "INFO" "CHECK -- Testcase to be checked for containerd"
  
}

#check_5_31() {
#  if [ -z "$containers" ]; then
#    return
#  fi

#  local id="5.31"
#  local desc="Ensure that the Docker socket is not mounted inside any containers (Automated)"
#  Testcase not applicable for containerd
#}

check_5_end() {
  endsectionjson
}
