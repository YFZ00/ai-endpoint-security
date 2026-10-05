from collectors.linux import (
    get_hostname,
    get_kernel_version,
    get_architecture,
    get_os_release,
    get_permit_root_login,
)

from engine.evaluator import evaluate_exact
from engine.policy_loader import load_policies


def main():
    print("=== AI Endpoint Security ===")
    print()

    # 1. Endpoint 기본 정보 수집
    hostname = get_hostname()
    kernel = get_kernel_version()
    architecture = get_architecture()
    os_release = get_os_release()

    print(f"Hostname     : {hostname}")
    print(f"OS           : {os_release.get('NAME', 'Unknown')}")
    print(f"Version      : {os_release.get('VERSION_ID', 'Unknown')}")
    print(f"Kernel       : {kernel}")
    print(f"Architecture : {architecture}")

    print()
    print("=== Security Findings ===")
    print()

    # 2. YAML 파일에서 보안 정책 읽기
    policies = load_policies("policies/linux.yaml")

    # 지금은 첫 번째 정책 하나만 사용
    policy = policies[0]

    # 3. 실제 Linux 설정값 수집
    actual = get_permit_root_login()

    # 4. YAML에 정의한 기대값 가져오기
    expected = policy["expected"]

    # 5. 실제값과 기대값 비교
    result = evaluate_exact(actual, expected)

    # 6. 결과 출력
    print(f"[{policy['id']}]")
    print(f"Title    : {policy['title']}")
    print(f"Expected : {expected}")
    print(f"Actual   : {actual}")
    print(f"Severity : {policy['severity']}")
    print(f"Result   : {result}")


if __name__ == "__main__":
    main()