# [Bandit] 커밋 분석 - b69b336
**주제:** 탐지 규칙 버그 수정 — B613(Trojan Source) 규칙이 stdin 입력에서 크래시하던 문제

---

## 🧩 개요
- **커밋 해시:** b69b336 (`b69b336450301d424e5ba04c9a58e8d41b7169b6`)
- **커밋 날짜:** 2026-02-22
- **파일 변경:** `bandit/plugins/trojansource.py` (+26 / -23)
- **관련 PR/이슈:**
  - 이슈: [PyCQA/bandit#1182](https://github.com/PyCQA/bandit/issues/1182) "Traceback when using passing file via stdin" (2024-10-02 등록)
  - PR: [PyCQA/bandit#1361](https://github.com/PyCQA/bandit/pull/1361)
- **관련 CVE/CWE:** [CVE-2021-42574](https://www.cve.org/CVERecord?id=CVE-2021-42574) (Trojan Source), [CWE-838](https://cwe.mitre.org/data/definitions/838.html)

---

## 📌 배경: Trojan Source 공격과 B613

**Trojan Source**(CVE-2021-42574)는 유니코드 **양방향 제어 문자**(bidi, 예: `U+202E`)를 코드에 몰래 넣는 공격이다.
이 문자는 화면에 보이지 않지만 글자 표시 순서를 뒤집기 때문에, **사람이 에디터·코드 리뷰 화면에서 보는 코드와 실제로 실행되는 코드가 달라진다.**

```python
# 사람 눈에는 문자열 비교 + 주석처럼 보이지만,
# 실제로는 제어 문자 때문에 조건문의 의미가 바뀐다
if access_level != 'none‮⁦': # Check if admin ⁩⁦' and access_level != 'user
```

리뷰어는 정상 코드로 승인하지만 실제로는 권한 검사가 우회되는 식이라, 코드 리뷰를 통과하는 **공급망 공격**에 쓰일 수 있다.
Bandit의 **B613**은 파이썬 파일에 이런 제어 문자가 들어 있으면 **High** 등급으로 경고하는 규칙이다 (2024-06 도입, `ec384b8`).

---

## 🐞 어떤 문제였나?

Bandit은 파일 대신 **표준 입력(stdin)** 으로 코드를 받아 검사할 수 있다.

```bash
cat app.py | bandit -
```

이때 B613만 다음 에러를 내며 죽었다.

```
[tester] ERROR Bandit internal error running: trojansource on file <stdin> at line 0:
[Errno 2] No such file or directory: '<stdin>'
```

### 왜 발생했나?
```python
# 수정 전
def trojansource(context):
    with open(context.filename, "rb") as src_file:      # ← 파일을 다시 열기
        encoding, _ = detect_encoding(src_file.readline)
    with open(context.filename, encoding=encoding) as src_file:
        ...
```

- 다른 규칙들은 Bandit이 이미 읽어둔 데이터(`context.file_data`)를 쓰는데, B613만 **파일 이름으로 디스크에서 파일을 다시 열었다.**
- stdin으로 받으면 실제 파일이 없고 파일 이름 자리에 `'<stdin>'`이라는 **표시용 문자열**만 들어 있다.
- 그래서 `'<stdin>'`이라는 파일을 열려다 `FileNotFoundError`가 났다.

즉 **"입력은 항상 디스크 위의 파일이다"라고 가정**한 것이 원인이다.

---

## 🔧 어떻게 고쳤나? (Diff 분석)

```diff
 def trojansource(context):
-    with open(context.filename, "rb") as src_file:
-        encoding, _ = detect_encoding(src_file.readline)
-    with open(context.filename, encoding=encoding) as src_file:
-        for lineno, line in enumerate(src_file.readlines(), start=1):
+    src_data = context.file_data
+    src_data.seek(0)
+    encoding, _ = detect_encoding(src_data.readline)
+    src_data.seek(0)
+    for lineno, line in enumerate(
+        src_data.read().decode(encoding).splitlines(), start=1
+    ):
         ...  # 이하 제어 문자 검사 로직은 동일 (들여쓰기만 변경)
```

- 파일을 다시 여는 대신 **Bandit이 이미 읽어둔 데이터 스트림(`context.file_data`)** 을 사용한다.
- `seek(0)`으로 처음으로 되감은 뒤 인코딩을 감지하고, 다시 되감아서 전체를 읽는다.
- 제어 문자를 찾는 핵심 로직은 그대로다. 바뀐 건 **"어디서 읽느냐"** 뿐이다.
- 덤으로 일반 파일을 검사할 때도 같은 파일을 두 번 더 여는 불필요한 작업이 사라졌다.

---

## 🧪 직접 검증: 수정 전/후 비교

수정 직전(`b69b336^`)과 수정 후(`b69b336`) 버전을 각각 설치하고, Bandit 저장소에 들어 있는 Trojan Source 예제(`examples/trojansource.py`, `U+202E` 포함)로 `-t B613`만 실행했다.

| 검사 방식 | 수정 전 | 수정 후 |
|---|---|---|
| 파일로 검사 `bandit file.py` | 탐지 ✅ (exit 1) | 탐지 ✅ (exit 1) |
| stdin으로 검사 `cat file.py \| bandit -` | **내부 에러 로그 + 탐지 실패, exit 0** ⚠️ | 탐지 ✅ (exit 1) |

### 핵심: 크래시가 "통과"로 처리됐다
수정 전 stdin 모드에서는 B613이 죽었는데도 **Bandit 전체 종료 코드는 `0`(문제 없음)** 이었다. (다른 규칙에서 걸린 게 없을 때 기준)

- CI/CD는 보통 **종료 코드로 성공/실패를 판단**한다.
- 그래서 stdin으로 Bandit을 돌리는 파이프라인(에디터 플러그인, pre-commit 훅, 스크립트 등)에서는 **Trojan Source가 들어간 코드가 "보안 검사 통과"로 머지될 수 있었다.**
- 에러 로그는 찍히지만, 로그를 사람이 직접 읽지 않으면 아무도 모른다.

이런 동작을 **Fail-Open**(검사가 실패하면 통과시킴)이라고 한다. 보안 검사는 보통 반대인 **Fail-Closed**(검사가 실패하면 막음)가 안전하다.

---

## 🔐 보안 관점 분석

| 구분 | 수정 전 | 수정 후 | 보안적 의미 |
|------|------|------|------|
| 데이터 출처 | 디스크에서 파일 재오픈 | 이미 읽은 스트림 재사용 | 입력 방식과 무관하게 동작 |
| stdin 검사 | 크래시 → 탐지 실패 | 정상 탐지 | **탐지 우회 경로 제거** |
| 실패 시 결과 | exit 0 (통과) | — | Fail-Open 문제 해소 (이 규칙에 한해) |
| 방치 기간 | 이슈 등록 2024-10 → 수정 2026-02 | | 약 1년 4개월 동안 stdin 사용자는 B613 보호를 못 받음 |

### 근본 원인
- 규칙 하나가 **다른 규칙과 다른 방식으로 입력을 읽었다**(일관성 없음).
- 처음 규칙을 추가할 때 **stdin 입력에 대한 테스트가 없었다.** 이슈 작성자(Bandit 메인테이너)도 "규칙을 추가할 때 단위 테스트가 이걸 잡았어야 했다"고 적었다.

### 남은 위험 (개인 의견)
- 이번 수정은 B613 하나만 고쳤다. **"규칙 내부 에러가 나도 전체 종료 코드는 0"** 이라는 Bandit의 동작 자체는 그대로다.
- 다른 규칙에서 비슷한 크래시가 생기면 같은 Fail-Open 문제가 다시 생길 수 있다.
- CI에서 Bandit을 쓴다면 종료 코드만 보지 말고 **JSON 출력의 `errors` 항목도 함께 확인**하는 것이 안전하다.

---

## 🧾 검증 및 확인
- [x] 관련 PR/이슈 확인 (#1182, #1361)
- [x] 보안 패치(CVE) 여부 확인 → Bandit 자체의 CVE는 아님. **CVE-2021-42574 공격을 탐지하는 규칙**의 버그 수정
- [x] 수정 전/후 버전 직접 실행해서 비교 (파일 모드 / stdin 모드, 종료 코드 포함)

---

## 💬 결론
- [x] 업데이트 성격: **보안 탐지 규칙 버그 수정** (크래시 해결 → 탐지 누락 해소)
- [x] CI/CD 신뢰성 영향: **있음** — stdin 기반 파이프라인에서 Trojan Source가 통과하던 문제 해결
- [x] 추가 확인 필요사항: 규칙 내부 에러 시 전체 결과를 실패로 처리하는 옵션이 필요한지

### 배운 점
- **"파일은 항상 디스크에 있다"는 가정은 깨질 수 있다.** stdin, 파이프, 메모리 버퍼 등 입력 경로가 여러 개면 모두 테스트해야 한다.
- **보안 도구가 조용히 죽으면 "안전함"으로 보인다.** 에러가 났을 때 통과(Fail-Open)인지 차단(Fail-Closed)인지 확인해야 한다.
- 비슷한 코드를 볼 때 의심할 것: 이미 읽어둔 데이터가 있는데 **파일을 다시 여는 코드**, 그리고 `try/except`나 상위 로직이 **예외를 삼키고 계속 진행하는 구조**

---

## 📚 참고
- 이슈: https://github.com/PyCQA/bandit/issues/1182
- PR: https://github.com/PyCQA/bandit/pull/1361
- B613 문서: https://bandit.readthedocs.io/en/latest/plugins/b613_trojansource.html
- Trojan Source: https://trojansource.codes/
- CVE-2021-42574: https://www.cve.org/CVERecord?id=CVE-2021-42574
- CWE-838: https://cwe.mitre.org/data/definitions/838.html
- B613 최초 도입 커밋: `ec384b8` New check: B113: TrojanSource - Bidirectional control characters (#757)
