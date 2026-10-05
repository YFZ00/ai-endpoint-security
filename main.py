import json

from collectors.linux import (
    get_hostname,
    get_kernel_version,
    get_architecture,
    get_os_release,
    get_permit_root_login,
    get_password_authentication,
)

from engine.evaluator import evaluate_exact
from engine.policy_loader import load_policies
from engine.finding import create_finding


COLLECTORS = {
    "permit_root_login": get_permit_root_login,
    "password_authentication": get_password_authentication,
}


def main():
    print("=== AI Endpoint Security ===")
    print()

    # Endpoint 기본 정보 수집
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

    # YAML 정책 불러오기
    policies = load_policies("policies/linux.yaml")

    # 점검 결과들을 저장할 리스트
    findings = []

    # 정책을 하나씩 순회
    for policy in policies:
        collector_name = policy["collector"]

        # YAML에 적힌 collector 이름과
        # 실제 Python 함수를 연결
        collector = COLLECTORS.get(collector_name)

        # 등록되지 않은 collector면 해당 정책은 건너뜀
        if collector is None:
            print(f"[{policy['id']}]")
            print(f"Error    : Unknown collector '{collector_name}'")
            print()
            continue

        # 실제 서버 설정값 수집
        actual = collector()

        # YAML에 정의된 기대값
        expected = policy["expected"]

        # 실제값과 기대값 비교
        result = evaluate_exact(
            actual,
            expected,
        )

        # 하나의 Finding 데이터 생성
        finding = create_finding(
            policy=policy,
            actual=actual,
            result=result,
        )

        # 전체 Finding 목록에 추가
        findings.append(finding)

        # 화면 출력
        print(f"[{finding['id']}]")
        print(f"Title    : {finding['title']}")
        print(f"Expected : {finding['expected']}")
        print(f"Actual   : {finding['actual']}")
        print(f"Severity : {finding['severity']}")
        print(f"Result   : {finding['result']}")
        print()

    # 모든 정책 점검이 끝난 뒤 JSON 파일로 저장
    with open("findings.json", "w", encoding="utf-8") as file:
        json.dump(
            findings,
            file,
            indent=2,
            ensure_ascii=False,
        )


if __name__ == "__main__":
    main()