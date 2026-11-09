# [Bandit] 커밋 분석 - 765f00d
**주제:** 탐지 규칙 범위 조정 — B614(안전하지 않은 PyTorch 모델 로드) 오탐 수정

---

## 🧩 개요
- **커밋 해시:** 765f00d (`765f00d3f202f83f61d03f882f80a2d5142d81f8`)
- **커밋 날짜:** 2026-01-11
- **파일 변경:**
  - `bandit/plugins/pytorch_load.py` (+12 / -16)
  - `examples/pytorch_load.py` (+4, 테스트 예제 추가)
- **관련 PR/이슈:**
  - 이슈: [PyCQA/bandit#1343](https://github.com/PyCQA/bandit/issues/1343) "B614: false positive on `torch.utils.cpp_extension.load`"
  - PR: [PyCQA/bandit#1348](https://github.com/PyCQA/bandit/pull/1348)
- **관련 CWE:** [CWE-502](https://cwe.mitre.org/data/definitions/502.html) Deserialization of Untrusted Data

---

## 📌 배경: torch.load가 왜 위험한가?

`torch.load()`는 PyTorch 모델 파일(`.pth`, `.pt`)을 불러오는 함수인데, 내부적으로 파이썬의 **pickle** 형식을 쓴다.
pickle은 데이터를 복원하면서 **임의의 파이썬 코드를 실행할 수 있다.** 그래서 인터넷에서 받은 모델 파일을 그냥 `torch.load()`로 열면, 그 파일 안에 숨겨진 코드가 내 컴퓨터에서 실행될 수 있다(역직렬화 취약점, CWE-502).

```python
torch.load("model.pth")                     # ❌ 위험: 파일 안의 코드가 실행될 수 있음
torch.load("model.pth", weights_only=True)  # ✅ 안전: 텐서 데이터만 불러옴
```

Bandit의 **B614**는 `weights_only=True` 없이 `torch.load`를 쓰는 코드를 찾아 경고하는 규칙이다 (2024-09 도입 `36fd650`, 2025-02 `8ff25e0`에서 현재 형태로 정리).

---

## 🐞 어떤 문제였나? (오탐)

모델 로딩과 전혀 상관없는 함수에도 경고가 떴다.

```python
torch.utils.cpp_extension.load(name="ext", sources=[...])   # ❌ 경고 (오탐)
```

`torch.utils.cpp_extension.load`는 **C++ 확장 모듈을 컴파일해서 불러오는 함수**로, pickle 역직렬화와 관계가 없고 `weights_only` 인자도 없다. 그래서 경고를 없앨 방법도 없었다.

### 왜 발생했나?
```python
# 수정 전
qualname_list = qualname.split(".")      # "torch.utils.cpp_extension.load" → [...]
func = qualname_list[-1]                 # "load"
if all(["torch" in qualname_list, func == "load"]):
    ...  # 경고
```

- 함수 전체 이름에 **`torch`가 들어 있고, 마지막 이름이 `load`이기만 하면** 전부 경고했다.
- 즉 `torch.아무거나.load` 형태면 모두 걸렸다. **규칙이 너무 넓었던 것**이 원인이다.

---

## 🔧 어떻게 고쳤나? (Diff 분석)

```diff
-    qualname_list = qualname.split(".")
-    func = qualname_list[-1]
-    if all(
-        [
-            "torch" in qualname_list,
-            func == "load",
-        ]
-    ):
+    if qualname in {"torch.load", "torch.serialization.load"}:
         # For torch.load, check if weights_only=True is specified
         weights_only = context.get_call_arg_value("weights_only")
```

- "이름 패턴이 비슷하면 경고"(블랙리스트 패턴) → **"정확히 이 두 함수만 경고"(허용 목록, allowlist)** 로 바꿨다.
- `torch.serialization.load`는 `torch.load`의 원래 정의 위치라 같이 넣었다.
- 문서에 적힌 CWE 번호를 실제 코드와 맞게 CWE-94 → **CWE-502**로 고쳤다. (탐지 결과에 찍히는 CWE는 원래부터 502였다.)
- 오탐 재발을 막기 위해 `torch.utils.cpp_extension.load` 예제를 "경고하면 안 되는 케이스"로 추가했다.

PR 작성자도 본문에서 트레이드오프를 직접 언급했다.
> "PyTorch가 pickle을 쓰는 로더를 새로 추가하면 이 목록을 업데이트해야 한다 — 오탐을 줄이는 대신 감수하는 부분"

---

## 🧪 직접 검증: 수정 전/후 비교

수정 직전(`765f00d^`)과 수정 후(`765f00d`) 버전을 각각 설치하고 같은 파일에 `bandit -t B614`를 실행했다.

| # | 코드 | 수정 전 | 수정 후 | 평가 |
|---|------|:---:|:---:|------|
| 1 | `torch.load("model.pth")` | 경고 | 경고 | 정상 |
| 2 | `torch.load(..., weights_only=True)` | 통과 | 통과 | 정상 |
| 3 | `torch.utils.cpp_extension.load(...)` | 경고 | 통과 | **오탐 해결** ✅ |
| 4 | `torch.serialization.load("model.pth")` | 경고 | 경고 | 정상 |
| 5 | `torch.hub.load("someone/repo", "model")` | 경고 | **통과** | **탐지 범위에서 빠짐** ⚠️ |
| 6 | `torch.jit.load("model.pt")` | 경고 | **통과** | **탐지 범위에서 빠짐** ⚠️ |

별칭으로 불러도 제대로 잡는지도 확인했다. 수정 후에도 모두 탐지됐다.

| 코드 | 수정 전 | 수정 후 |
|------|:---:|:---:|
| `import torch as t` → `t.load(...)` | 경고 | 경고 |
| `from torch import load` → `load(...)` | 경고 | 경고 |
| `from torch.serialization import load as sload` → `sload(...)` | 경고 | 경고 |

→ 이슈의 오탐(3)은 해결됐고 핵심 대상(1, 4)과 별칭 호출도 그대로 잡는다. 대신 **`torch.hub.load`(5)와 `torch.jit.load`(6)는 더 이상 경고하지 않는다.**

---

## 🔐 보안 관점 분석

### 1. 오탐 해결은 타당하다
`cpp_extension.load`는 역직렬화와 무관하니 경고하지 않는 게 맞다. 경고를 끌 방법도 없는 오탐은 개발자가 B614 자체를 꺼버리게 만들어 오히려 위험하다.

### 2. ⚠️ `torch.hub.load`가 빠진 건 짚어볼 만하다
- `torch.hub.load("someone/repo", "model")`은 **GitHub 저장소를 내려받아 그 안의 `hubconf.py` 코드를 실행**하는 함수다.
- 즉 저장소 주인이 악의적이면 **원격 코드가 그대로 내 환경에서 실행된다.** 엄밀히는 pickle 역직렬화(CWE-502)가 아니라 "무결성 검증 없는 코드 다운로드"(CWE-494) 쪽 문제다.
- 수정 전에는 이름 패턴 덕분에 **우연히** 경고가 떴지만, 수정 후에는 경고가 없다.
- Bandit 플러그인 목록을 확인해 보니 **`torch.hub`을 따로 검사하는 규칙은 없다.** 결과적으로 이 위험한 호출은 Bandit에서 아무 경고도 받지 않게 되었다.

### 3. `torch.jit.load`
- TorchScript 모델을 불러오는 함수로, 이번 수정으로 검사 대상에서 빠졌다.
- `torch.load`와 내부 동작이 달라 위험 수준이 같다고 단정할 수는 없다. 신뢰할 수 없는 모델 파일이라면 별도로 확인이 필요하다.

| 구분 | 수정 전 | 수정 후 | 보안적 의미 |
|------|------|------|------|
| 탐지 방식 | `torch.*.load` 패턴 | `torch.load`, `torch.serialization.load`만 | 정확도↑, 범위↓ |
| 오탐 | `cpp_extension.load` 등 경고 | 해결 | 경고 피로 감소 |
| 미탐 | 거의 없음 | `torch.hub.load`, `torch.jit.load` 등 경고 없음 | 일부 위험 호출이 사각지대로 |
| 유지보수 | 자동으로 넓게 잡음 | PyTorch에 새 로더가 생기면 목록 수동 갱신 필요 | 목록이 낡으면 미탐 증가 |

### 4. 더 나은 방법은 없었을까? (개인 의견)
- `torch.hub.load`는 성격이 다르니 B614에 억지로 넣기보다, **B615(Hugging Face 무결성 미검증 다운로드)처럼 별도 규칙**으로 다루는 게 맞아 보인다.
- 허용 목록 방식을 유지한다면, 이번처럼 "경고하면 안 되는 예제"뿐 아니라 **"경고해야 하는 예제"(torch.hub.load 등)도 테스트에 넣어서** 범위가 줄어든 걸 의도적으로 결정했는지 남겨두면 좋다.

---

## 🧾 검증 및 확인
- [x] 관련 PR/이슈 확인 (#1343, #1348)
- [x] 보안 패치(CVE) 여부 확인 → CVE 아님. 보안 탐지 규칙의 **정확도 개선**(오탐 수정)
- [x] 수정 전/후 버전 직접 실행해서 비교 (6가지 호출 + 별칭 3가지)
- [x] 다른 Bandit 규칙이 `torch.hub`을 검사하는지 확인 → 없음

---

## 💬 결론
- [x] 업데이트 성격: **탐지 규칙 정확도 개선 (오탐 수정)** — 단, 탐지 범위가 함께 좁아짐
- [x] CI/CD 신뢰성 영향: **있음** — B614 경고가 줄어듦 (불필요한 경고 감소 + 일부 위험 호출 미탐)
- [x] 추가 확인 필요사항: `torch.hub.load` 같은 원격 코드 로딩을 잡는 규칙이 필요한지

### 배운 점
- **블랙리스트 패턴 vs 허용 목록:** 넓게 잡으면 오탐, 좁게 잡으면 미탐이다. 허용 목록은 정확하지만 **목록이 낡으면 조용히 놓친다.**
- **"우연히 잡던 것"도 잡던 것이다.** 규칙을 좁힐 때는 원래 의도와 상관없이 그동안 막아주던 게 뭐였는지 확인해야 한다.
- 비슷한 코드를 볼 때 의심할 것: `torch.load`, `pickle.load`, `torch.hub.load`처럼 **외부에서 받은 데이터나 코드를 "불러오는(load)" 함수** — 특히 출처를 신뢰할 수 없는 경우

---

## 📚 참고
- 이슈: https://github.com/PyCQA/bandit/issues/1343
- PR: https://github.com/PyCQA/bandit/pull/1348
- B614 문서: https://bandit.readthedocs.io/en/latest/plugins/b614_pytorch_load.html
- PyTorch `torch.load` 문서 (weights_only): https://pytorch.org/docs/stable/generated/torch.load.html
- PyTorch Hub 문서: https://pytorch.org/docs/stable/hub.html
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- B614 최초 도입 커밋: `36fd650` Pytorch Load / Save Plugin (#1114), 이후 `8ff25e0` Pytorch fix (#1231)
