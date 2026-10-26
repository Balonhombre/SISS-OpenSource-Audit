# [Bandit] 커밋 분석 - 8f2f928
**주제:** 탐지 규칙 수정 — B615(Hugging Face 무결성 미검증 다운로드) 오탐 해결

---

## 🧩 개요
- **커밋 해시:** 8f2f928 (`8f2f9284fca830ca017b2e2cc3ddc2a7b74b7040`)
- **커밋 날짜:** 2026-02-23
- **파일 변경:**
  - `bandit/plugins/huggingface_unsafe_download.py` (+14 / -1)
  - `examples/huggingface_unsafe_download.py` (+15, 테스트 예제 추가)
- **관련 PR/이슈:**
  - 이슈: [PyCQA/bandit#1345](https://github.com/PyCQA/bandit/issues/1345) "B615: false positive if set revision as variable"
  - PR: [PyCQA/bandit#1358](https://github.com/PyCQA/bandit/pull/1358)
- **관련 CWE:** [CWE-494](https://cwe.mitre.org/data/definitions/494.html) Download of Code Without Integrity Check

---

## 📌 배경: B615는 무엇을 잡는 규칙인가?

Hugging Face Hub에서 모델·데이터셋을 받을 때 `revision`을 지정하지 않거나 `"main"`, `"v1.0"` 같은 **브랜치/태그 이름**으로 받으면 위험하다.
브랜치나 태그는 **나중에 다른 내용을 가리키도록 바꿀 수 있기 때문**에, 저장소가 탈취되면 같은 이름으로 악성 모델 파일이 내려올 수 있다(공급망 공격).

그래서 B615는 **바뀌지 않는 커밋 해시(16진수 7자 이상)** 로 고정(pinning)했을 때만 안전하다고 본다.

```python
AutoModel.from_pretrained("org/model")                        # ❌ 경고
AutoModel.from_pretrained("org/model", revision="main")       # ❌ 경고
AutoModel.from_pretrained("org/model", revision="548fc3543a") # ✅ 통과
```

---

## 🐞 어떤 문제였나? (오탐, False Positive)

커밋 해시를 **변수에 담아서** 넘기면, 올바르게 고정했는데도 경고가 떴다.

```python
MODEL_REVISION = "548fc3543a"   # 커밋 해시
AutoModel.from_pretrained(MODEL_ID, revision=MODEL_REVISION)  # ❌ 경고 (오탐)
```

### 왜 발생했나?
Bandit은 코드를 실행하지 않고 **문법 트리(AST)만 보고** 판단하는 정적 분석 도구다.
`revision` 값을 꺼내는 함수 `get_call_arg_value()`는 변수를 만나면 **변수 안의 값이 아니라 변수 이름**을 돌려준다.

| 넘긴 값 | `get_call_arg_value()` 결과 | 판정 |
|------|------|------|
| `revision="548fc3543a"` | `"548fc3543a"` | 16진수 → 통과 |
| `revision=MODEL_REVISION` | `"MODEL_REVISION"` (변수 **이름**) | 16진수 아님 → **경고** |
| `revision=config["revision"]` | `None` | "revision 없음"과 구분 불가 → **경고** |

즉 **"값을 알 수 없음"을 "값이 없음/위험함"으로 처리**한 것이 원인이다.

---

## 🔧 어떻게 고쳤나? (Diff 분석)

```diff
-    # Check for revision parameter (the key security control)
+    # Check for revision parameter (the key security control).
+    # First, check the raw AST to see if a revision/commit_id keyword was
+    # passed as a non-literal expression (variable, attribute, subscript,
+    # function call, etc.).  In those cases we cannot statically determine
+    # the value, so we give the user the benefit of the doubt.
+    call_node = context._context.get("call")
+    if call_node is not None:
+        for kw in getattr(call_node, "keywords", []):
+            if kw.arg in ("revision", "commit_id") and not isinstance(
+                kw.value, ast.Constant
+            ):
+                return
```

- 함수 호출의 키워드 인자 중 `revision`/`commit_id`를 찾는다.
- 그 값이 **문자열 리터럴(`ast.Constant`)이 아니면**, 즉 변수·딕셔너리 조회·함수 호출 등이면
- 값을 정적으로 알 수 없으니 **"사용자를 믿고(benefit of the doubt)" 경고를 내지 않고 바로 `return`** 한다.

---

## 🧪 직접 검증: 수정 전/후 비교

수정 직전(`8f2f928^`)과 수정 후(`8f2f928`) 버전을 각각 설치해서 같은 파일에 `bandit -t B615`를 돌려봤다.

```python
MODEL_REVISION = "548fc3543a"
BRANCH = "main"
config = {"revision": "abc1234567"}
```

| # | 코드 | 실제로 안전? | 수정 전 | 수정 후 | 평가 |
|---|------|:---:|:---:|:---:|------|
| 1 | `revision` 없음 | ❌ | 경고 | 경고 | 정상 |
| 2 | `revision="main"` | ❌ | 경고 | 경고 | 정상 |
| 3 | `revision="548fc3543a"` | ✅ | 통과 | 통과 | 정상 |
| 4 | `revision=MODEL_REVISION` | ✅ | 경고 | 통과 | **오탐 해결** ✅ |
| 5 | `revision=config["revision"]` | ✅ | 경고 | 통과 | **오탐 해결** ✅ |
| 6 | `revision=BRANCH` (`"main"`) | ❌ | 경고 | **통과** | **새 미탐 발생** ⚠️ |
| 7 | `revision=os.environ.get("REV", "main")` | ❌ | 경고 | **통과** | **새 미탐 발생** ⚠️ |

→ 이슈에서 말한 오탐(4, 5)은 해결됐지만, **변수 안에 브랜치 이름이 들어 있는 위험한 코드(6, 7)도 같이 통과**하게 되었다.

---

## 🔐 보안 관점 분석

| 구분 | 수정 전 | 수정 후 | 보안적 의미 |
|------|------|------|------|
| 판단 기준 | 값을 모르면 위험으로 간주 | 값을 모르면 안전으로 간주 | **보수적 → 관대한** 방향으로 전환 |
| 오탐 (False Positive) | 변수로 넘긴 해시도 경고 | 해결 | 개발자 불편·경고 피로 감소 |
| 미탐 (False Negative) | 거의 없음 | 변수/환경변수로 넘긴 `"main"` 등 놓침 | 공급망 공격 탐지 범위 축소 |

### 트레이드오프
- **오탐이 많으면** 개발자들이 경고를 무시하거나 `# nosec`으로 전부 꺼버린다(경고 피로). 결국 규칙 자체가 쓸모없어진다.
- **미탐이 생기면** 진짜 위험한 코드가 "검사 통과"라는 착각과 함께 배포된다.
- 이번 수정은 사용성을 위해 **"정적 분석으로 알 수 없는 경우는 통과"** 를 선택했다. 실무에서 흔한 방식이지만, 그만큼 탐지 범위가 줄었다는 점은 알고 써야 한다.

### 더 나은 방법은 없었을까? (개인 의견)
- 같은 파일 안에서 변수에 **문자열 상수가 대입된 경우**(`BRANCH = "main"`)는 그 값을 따라가서 검사할 수 있다. 그러면 4번은 통과, 6번은 경고로 둘 다 잡을 수 있다.
- 값을 끝내 알 수 없는 경우(7번처럼 환경변수 등)는 경고를 아예 끄기보다 **신뢰도(confidence)를 LOW로 낮춰서 보고**하는 방법도 있다. Bandit은 이미 이슈마다 severity/confidence를 따로 매기는 구조라 잘 맞는다.

---

## 🧾 검증 및 확인
- [x] 관련 PR/이슈 확인 (#1345, #1358)
- [x] 보안 패치(CVE) 여부 확인 → CVE 아님. 보안 탐지 규칙의 **정확도 개선**(오탐 수정)
- [x] 수정 전/후 버전 직접 실행해서 동작 비교 (위 표)
- [x] 수정 후에도 기존 위험 패턴(1, 2)은 그대로 탐지되는지 확인

---

## 💬 결론
- [x] 업데이트 성격: **탐지 규칙 정확도 개선 (오탐 수정)** — 단, 일부 미탐이 새로 생김
- [x] CI/CD 신뢰성 영향: **있음** — Bandit을 CI에서 돌리는 프로젝트는 B615 경고가 줄어듦 (좋은 쪽 + 놓치는 쪽 모두)
- [x] 추가 확인 필요사항: 변수 값 추적 또는 낮은 신뢰도로 보고하는 방식으로 미탐을 줄일 수 있는지

### 배운 점
- **정적 분석 도구는 "모름"을 어떻게 처리하느냐가 핵심이다.** 모르는 걸 위험으로 보면 오탐, 안전으로 보면 미탐이 생긴다.
- **오탐 수정은 미탐을 만들 수 있다.** 버그를 고친 PR도 "원래 잡던 것을 여전히 잡는지" 반대 방향으로 테스트해봐야 한다. 이번 PR의 테스트 예제(#24, #25)는 "안전한데 경고 뜨던 것"만 추가했고, "위험한데 변수로 넘긴 것"은 추가하지 않았다.
- **보안 도구의 "통과"가 "안전"을 뜻하지는 않는다.** 내 코드가 B615를 통과해도, 변수에 실제로 커밋 해시가 들어 있는지는 직접 확인해야 한다.

---

## 📚 참고
- 이슈: https://github.com/PyCQA/bandit/issues/1345
- PR: https://github.com/PyCQA/bandit/pull/1358
- B615 문서: https://bandit.readthedocs.io/en/latest/plugins/b615_huggingface_unsafe_download.html
- B615 최초 도입 커밋: `2d0b675` Huggingface revision pinning (#1281)
- CWE-494: https://cwe.mitre.org/data/definitions/494.html
- Hugging Face 다운로드 가이드: https://huggingface.co/docs/huggingface_hub/en/guides/download
