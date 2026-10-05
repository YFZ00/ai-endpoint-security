from collectors.linux import (
    get_hostname,
    get_kernel_version,
    get_architecture,
    get_os_release,
)


def main():
    print("=== AI Endpoint Security ===")
    print()

    hostname = get_hostname()
    kernel = get_kernel_version()
    architecture = get_architecture()
    os_release = get_os_release()

    print(f"Hostname     : {hostname}")
    print(f"OS           : {os_release.get('NAME', 'Unknown')}")
    print(f"Version      : {os_release.get('VERSION_ID', 'Unknown')}")
    print(f"Kernel       : {kernel}")
    print(f"Architecture : {architecture}")


if __name__ == "__main__":
    main()