# TODOS

## Prove Output / Solidity Integration

### P1 — 수정 계획 수립 중

**#1: proof_to_solidity — canonical Solidity 트레잇 사용으로 교체**
- **Priority:** P1
- **What:** `proof_to_solidity()`가 `.to_string()` 직접 호출. `ark-utils`의 `Solidity` 트레잇은 zero-check 포함 (`"0"` 처리). 현재 구현은 canonical `dto/proof.rs`와 코드 분기.
- **Impact:** BN254 유효 증명에서는 c0/c1이 0이 될 수 없어 프로덕션 위험 낮음. 단, canonical 구현 변경 시 SDK가 자동으로 따라가지 못함 (3곳 중복: sdk-node, sdk-rn, circuit repo).
- **Fix direction:** `ark-utils` crate를 의존성으로 추가하고 `.to_solidity()` 호출로 교체, 또는 최소한 zero-check 추가.

**#4: shared_inputs — JWT 간 불일치 무음 오류**
- **Priority:** P1
- **What:** `split_public_inputs()`가 `pub_inputs[0]`의 값만 추출해 shared로 반환. 여러 JWT 증명 시 각 row의 shared 필드가 실제로 동일한지 검증하지 않음. 불일치 시 잘못된 값이 Solidity verifier에 전달되며 진단 불가.
- **Impact:** 동일한 anchor/root/h_sign_user_op를 사용하도록 회로가 보장하지만, SDK 레벨에서 assert 없음. 회로 버그 발생 시 무음 실패.
- **Fix direction:** `pub_inputs` 전체를 순회하며 shared 인덱스 값이 모두 동일한지 검증 후, 불일치 시 명시적 에러 반환.

---

### P2 — 추후 개선

**#2: verify() — prove() 출력과 호환 불가**
- **Priority:** P2
- **What:** `verify()`는 `Buffer`(ark_serialize) 포맷 요구, `prove()`는 decimal string 반환. 현재 공개 API에서 prove → verify 흐름이 불가능.
- **Fix direction:** `verify`를 decimal string 배열 입력을 받도록 업데이트하거나, `verifyDecimal` 별도 export 추가.

**#3: split_public_inputs — inner row 길이 미검사**
- **Priority:** P2
- **What:** `row[JWT_EXP_INDEX]`, `row[PARTIAL_RHS_INDEX]` 접근 시 row 길이 < 6이면 panic. 내부 함수라 현재 위험 낮음.
- **Fix direction:** `row.len() > PARTIAL_RHS_INDEX` 검사 후 에러 반환.

**#7: 혼합 인코딩 — hash/anchor는 0x hex, prove는 decimal**
- **Priority:** P2
- **What:** `generateHash`, `generateAnchor` 등은 `"0x..."` hex 반환, `prove()` 출력 필드는 decimal. 두 값을 비교/조합하면 불일치.
- **Fix direction:** API 문서에 명시적으로 인코딩 차이 문서화, 또는 변환 유틸 export.

**#8: proof_to_solidity 로직 3중 중복**
- **Priority:** P3
- **What:** sdk-node, sdk-rn, circuit repo `dto/proof.rs`에 동일 로직 존재. canonical 변경 시 SDK 2곳이 자동으로 업데이트 안 됨.
- **Fix direction:** `ark-utils` 또는 별도 shared crate로 추출.

---

## Completed
