# [Bandit] 커밋 분석 - 7137a9d
**주제:** GitHub Actions 의존성 업데이트 (sigstore/cosign-installer v4.1.1 → v4.1.2)

---

## 🧩 개요
- **커밋 해시:** 7137a9d (`7137a9d59b5965bb9a89a79636742ab48fb5a61b`)
- **커밋 날짜:** 2026-05-11 (작성자: dependabot[bot])
- **파일 변경:** `.github/workflows/build-publish-image.yml` (1줄)
- **관련 PR/릴리즈:**
  - Bandit PR: [PyCQA/bandit#1413](https://github.com/PyCQA/bandit/pull/1413)
  - cosign-installer 릴리즈: [v4.1.2](https://github.com/sigstore/cosign-installer/releases/tag/v4.1.2)

---

## 🔍 변경 요약

Bandit은 Docker 이미지를 빌드해서 `ghcr.io`에 올린 뒤, **Cosign으로 이미지에 서명**한다.
이 커밋은 Cosign을 설치해주는 GitHub Action(`sigstore/cosign-installer`)의 버전을 올린 것이다.

```diff
     - name: Install Cosign
-      uses: sigstore/cosign-installer@cad07c2e89fa2edd6e2d7bab4c1aa38e53f76003 # v4.1.1
+      uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2
       with:
         cosign-release: 'v2.2.2'
```

- 버전을 태그(`@v4.1.2`)가 아닌 **커밋 SHA로 고정(pinning)** 하고, 사람이 읽을 수 있게 주석으로 버전을 적어둠
- cosign-installer v4.1.2의 변경 내용은 사실상 하나: **기본 설치 Cosign 버전을 3.0.6으로 올림** ([cosign-installer#232](https://github.com/sigstore/cosign-installer/pull/232))

---

## 🔐 보안 관점 분석

### 1. 이 업데이트가 원래 막으려던 것
cosign-installer v4.1.2가 기본으로 설치하는 **Cosign v3.0.6**은 아래 보안 문제를 고친 버전이다.

| 항목 | 내용 |
|------|------|
| 취약점 | [GHSA-w6c6-c85g-mmv6](https://github.com/sigstore/cosign/security/advisories/GHSA-w6c6-c85g-mmv6) / CVE-2026-39395 (Medium) |
| 문제 | `cosign verify-blob-attestation`에서 증명(attestation) 파싱 중 에러가 나도 **에러를 무시하고 "검증 성공"으로 보고** |
| 영향 버전 | Cosign ≤ v3.0.5, ≤ v2.6.2 |
| 수정 커밋 | sigstore/cosign `f1ad3ee9` "Fix DSSE predicate check" |

→ 즉 v4.1.2 업데이트의 목적은 **"검증이 통과되면 안 되는 걸 통과시키는" 버그가 고쳐진 Cosign을 쓰게 하는 것**이다.

### 2. ⚠️ 그런데 Bandit에는 이 효과가 적용되지 않는다

diff를 다시 보면 바로 아래 줄에 이런 설정이 있다.

```yaml
with:
  cosign-release: 'v2.2.2'
```

`cosign-release`는 **설치할 Cosign 버전을 직접 지정**하는 옵션이다.
이 값은 2024-01 이미지 배포 기능이 처음 생겼을 때(`ff7ed4b`, #1088) 들어간 뒤로 **한 번도 바뀌지 않았다.**

| 구분 | 이전 (v4.1.1) | 변경 (v4.1.2) | 보안적 의미 |
|------|------------|------------|--------------|
| cosign-installer (설치 도구) | v4.1.1 | v4.1.2 | 설치 도구 자체는 최신화됨 |
| 기본 Cosign 버전 | v3.0.5 | v3.0.6 | CVE-2026-39395 수정본 |
| **Bandit이 실제로 쓰는 Cosign** | **v2.2.2** | **v2.2.2** | **변화 없음. 고쳐진 버전이 적용되지 않음** |

v2.2.2는 2023년 말 버전으로, 이후 공개된 여러 보안 공지의 영향 범위에 들어간다.

| 보안 공지 | 심각도 | 영향 버전 | 내용 |
|------|------|------|------|
| CVE-2024-29902 | Medium | ≤ 2.2.3 | 악성 첨부물로 시스템 전체 DoS 가능 |
| CVE-2024-29903 | Medium | ≤ 2.2.3 | 악성 아티팩트로 머신 전체 DoS 가능 |
| CVE-2026-22703 | Medium | ≤ 2.6.1 | 특정 조건에서 아무 Rekor 항목이나 검증 통과 |
| CVE-2026-39395 | Medium | ≤ 2.6.2 | 증명 파싱 실패해도 검증 성공으로 보고 |
| GHSA-fx35-mq7g-6g98 | High | ≤ 2.6.4 | 레거시 번들의 공개키로 검증 우회 |

### 3. 실제 위험도는? (과장하지 않기)
- 위 취약점들은 대부분 **검증(verify)·다운로드 쪽** 문제다.
- Bandit 워크플로는 Cosign을 **서명(`cosign sign`)에만** 사용하고 검증은 하지 않는다.
- 따라서 **Bandit 빌드 파이프라인이 당장 뚫리는 상황은 아니다.**
- 다만 cosign-installer 측은 v4.1.0 릴리즈 노트에서 *"특별한 이유가 없다면 `cosign-release` 사용을 강하게 권장하지 않는다"* 고 명시하고 있다. 오래된 버전 고정은 앞으로 서명 쪽에 취약점이 나와도 업데이트가 자동으로 반영되지 않는 구조라는 점에서 **공급망 보안 관리상 허점**이다.

---

## 🧾 검증 및 확인
- [x] 관련 PR/릴리즈 로그 확인 (PyCQA/bandit#1413, cosign-installer v4.1.2, cosign v3.0.6)
- [x] 보안 패치(CVE) 여부 확인 → 간접적으로 CVE-2026-39395 관련 (Cosign 기본 버전 상향)
- [x] 실제 적용 여부 확인 → `cosign-release: 'v2.2.2'` 고정으로 **Bandit에는 미적용**
- [ ] 테스트/빌드 정상 동작 확인

---

## 💬 결론
- [x] 업데이트 성격: **의존성 업데이트 (간접적 보안 강화)** — 단, Bandit에서는 실효성 없음
- [x] CI/CD 신뢰성 영향: **있음** — 이미지 서명 단계에 쓰이는 도구
- [x] 추가 확인 필요사항: `cosign-release` 버전 고정을 제거하거나 최신 버전으로 올리는 것이 맞는지

### 배운 점
- **"버전을 올렸다" ≠ "실제로 쓰는 버전이 바뀌었다"**
  Dependabot이 올려준 diff 한 줄만 보면 보안 업데이트가 반영된 것 같지만, 바로 아래 설정 때문에 실제 실행되는 바이너리는 그대로였다. diff는 **바뀐 줄뿐만 아니라 주변 맥락까지** 읽어야 한다.
- **설치 도구와 실제 도구는 별개다.** `*-installer`, `setup-*` 류 Action은 "무엇을 설치하는지"를 따로 확인해야 한다.
- **좋은 점도 있다.** Action을 태그가 아닌 커밋 SHA로 고정한 것은 태그 바꿔치기 공격을 막는 권장 방식이다.
- 비슷한 코드를 볼 때 의심할 것: 의존성 업데이트 커밋에서 `with:` 옵션으로 **하위 버전을 고정**하고 있지 않은지

---

## 📚 참고
- Bandit PR: https://github.com/PyCQA/bandit/pull/1413
- cosign-installer 릴리즈 노트: https://github.com/sigstore/cosign-installer/releases (v4.1.0, v4.1.2)
- cosign v3.0.6 릴리즈 노트: https://github.com/sigstore/cosign/releases/tag/v3.0.6
- Cosign 보안 공지 목록: https://github.com/sigstore/cosign/security/advisories
- 이전 오답노트: `bandit/docs/오답노트/*_e1ffdf6_Bump-cosign-4.0.0.md` (같은 Action의 3.10.0 → 4.0.0 업데이트)
