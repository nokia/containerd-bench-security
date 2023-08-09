# Contributing to containerd Bench for Security

Want to hack on containerd Bench? Awesome! Here are instructions to get you
started.

The containerd Bench for Security is a fork from the Docker Bench for Security.
Please, go read
[Contribute to the Moby Project](https://github.com/moby/moby/blob/master/CONTRIBUTING.md).

## Development Environment Setup

### Start hacking

You can build the container that wraps the containerd-bench for security:

```sh
git clone https://scm.cci.nokia.net/bekefi/containerd-security.git
cd containerd-security
docker build -t containerd-bench-security .
```

Or you can simply run the shell script locally:

```sh
git clone https://scm.cci.nokia.net/bekefi/containerd-security
cd containerd-security
sudo sh containerd-bench-security.sh
```

The benchmark has the main script called `containerd-bench-security.sh`.
This is the main script that checks for all the dependencies, deals with
command line arguments and loads all the tests.

The tests are split into the following files:

```sh
tests/
├── 1_host_configuration.sh
├── 2_daemon_configuration.sh
├── 3_daemon_configuration_files.sh
├── 4_container_images.sh
├── 5_container_runtime.sh
├── 6_security_operations.sh
|
└── 99_community_checks.sh
```

To modify the containerd Bench for Security you should first clone the repository,
make your changes, check your code with `shellcheck`, or similar tools, and
then sign off on your commits. After that feel free to send us a pull request
with the changes.

While this tool was inspired by the [CIS Docker 1.11.0 benchmark](https://www.cisecurity.org/benchmark/docker/)
and its successors, feel free to add new tests.
