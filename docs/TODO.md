# TODO: `downloadRelease` 개선 사항

이 문서는 `zkap-reference-app`에서 지갑 배포 전에 약 700MB proving
bundle을 내려받는 UX를 붙이면서 확인한 `@baerae/zkap-zkp`
`downloadRelease()`의 개선 사항을 정리한다.

## 구현 상태 (2026-06-02)

| # | 항목 | 상태 |
| --- | --- | --- |
| 1 | RN 실시간 progress | ✅ `expo-file-system` `createDownloadResumable`로 교체 |
| 2 | progress semantics 분리 | ✅ `artifact*`/`release*`/`percent` 추가, `loadedBytes`/`totalBytes` deprecated |
| 3 | RN download 교체 | ✅ progress 콜백 기반 다운로더 |
| 4 | RN artifact content SHA256 | ⏸ 미구현(설계 결정): RN은 size만 확인하고 prove-time native SHA gate에 위임. Node↔RN 차이를 문서에 명시 |
| 5 | AbortSignal/취소 | ✅ `DownloadReleaseOpts.signal` + tmp cleanup |
| 6 | cache 상태 API | ✅ `getCachedReleaseInfo()` (Node/RN) |
| 7 | 문서 | ✅ `API_REFERENCE.md`, `REACT_NATIVE_GUIDE.md`, `packages/sdk/README.md` 갱신 |

전체 release size(`releaseTotalBytes`/`percent`)는 manifest artifact size 합산으로
제공한다(항목 4의 "전체 size 미계산"도 해소). 테스트는 `packages/sdk/test/`에
vitest 단위 테스트로 추가했다(`npm run test:unit`). content SHA(항목 4)는
700MB 순수 JS 해싱 비용 때문에 의도적으로 보류했으며, native hashing이
필요하면 RN native 모듈 변경(재게시 필요)으로 후속 처리한다.

## 결론

`downloadRelease()`를 제거하거나 reference app에서 자체 구현으로 대체할
필요는 없다. release layout, shape별 파일명, cache key, staging directory,
manifest loading 규칙을 SDK가 소유하는 편이 맞다.

다만 React Native 구현은 대용량 모바일 다운로드 UX와 무결성 검증 관점에서
보완이 필요하다. 현재 앱은 SDK의 raw progress를 그대로 사용자에게 보여주지
말고, SDK 개선 전까지 wrapper에서 전체 bundle 기준 progress로 정규화해야
한다.

## 현재 구현

- `packages/sdk/src/node.ts`
  - `fetch()` response body를 stream으로 읽는다.
  - chunk마다 `loadedBytes`를 누적해 `onProgress`를 호출한다.
  - 다운로드와 동시에 SHA256을 계산하고 `<shape>-SHA256SUMS` 값과 비교한다.
- `packages/sdk/src/react-native.ts`
  - `expo-file-system/legacy`의 `downloadAsync()`를 사용한다.
  - 파일 다운로드가 끝난 뒤 `fileSize()`로 실제 크기를 읽고 그때 한 번
    `onProgress`를 호출한다.
  - manifest SHA와 artifact size는 확인하지만, 각 artifact content SHA256을
    Node 구현처럼 직접 검증하지 않는다.
- `packages/sdk/src/types.ts`
  - `DownloadReleaseProgress.loadedBytes` / `totalBytes`의 의미가
    "현재 artifact 기준"인지 "전체 release 기준"인지 타입에서 명확하지 않다.

## 문제점

### 1. React Native progress가 실시간이 아니다

React Native 구현은 `downloadAsync()` 완료 후에만 progress를 emit한다.
따라서 700MB에 가까운 `pk.bin`을 받는 동안 UI는 오래 멈춰 보일 수 있다.

필요한 개선:

- `expo-file-system`의 resumable/progress callback 지원 API 또는 별도 native
  downloader를 사용한다.
- 파일 내부 진행률을 chunk/progress event 단위로 전달한다.
- 큰 파일에서도 최소 수백 ms 간격으로 UI가 갱신되도록 throttle 정책을 둔다.

### 2. Progress semantics가 모호하다

현재 `DownloadReleaseProgress`는 다음 필드만 제공한다.

```ts
interface DownloadReleaseProgress {
  phase: 'metadata' | 'artifact' | 'stage' | 'done';
  artifact?: string;
  loadedBytes?: number;
  totalBytes?: number;
  completedArtifacts?: number;
  totalArtifacts?: number;
}
```

이 구조에서는 `loadedBytes / totalBytes`가 현재 artifact 기준인지 전체
release 기준인지 소비자가 오해하기 쉽다. reference app에서 진행바가 이상하게
보인 원인도 이 지점이다.

필요한 개선:

- per-artifact와 whole-release progress를 타입에서 분리한다.
- 권장 타입 예시:

```ts
interface DownloadReleaseProgress {
  phase: 'metadata' | 'artifact' | 'stage' | 'done';
  artifact?: string;
  artifactLoadedBytes?: number;
  artifactTotalBytes?: number;
  releaseLoadedBytes?: number;
  releaseTotalBytes?: number;
  completedArtifacts?: number;
  totalArtifacts?: number;
  percent?: number;
}
```

호환성을 위해 기존 `loadedBytes` / `totalBytes`는 당분간 유지하되,
문서에서 artifact 기준이라고 명시하거나 deprecated 처리한다.

### 3. React Native artifact SHA256 검증이 Node보다 약하다

Node 구현은 각 artifact를 stream으로 읽으며 SHA256을 계산하고,
`<shape>-SHA256SUMS`의 digest와 비교한다. React Native 구현은 다운로드 직후
크기만 확인한다. cached release 검증도 manifest에 적힌 size 확인에 머문다.

필요한 개선:

- React Native에서도 각 artifact SHA256을 계산해 `<shape>-SHA256SUMS` 또는
  manifest의 sha256과 비교한다.
- 큰 파일에서 JS thread 부담이 크면 native hashing 또는 chunked hashing을
  제공한다.
- 실패 시 tmp directory를 정리하고 명확한 integrity error를 던진다.

### 4. 전체 release size를 SDK가 계산하지 않는다

reference app은 사용자에게 약 700MB 다운로드를 고지해야 한다. 현재 SDK는
전체 bundle size를 명시적으로 제공하지 않으므로 앱이 추정값을 들고 있어야
한다.

필요한 개선:

- manifest의 artifact size를 합산해 `releaseTotalBytes`를 계산한다.
- `downloadRelease()` 시작 직후 metadata/manifest 단계에서 전체 예상 크기를
  progress로 알려준다.
- cached release인 경우에도 result에 `totalBytes` 또는 `artifacts` metadata를
  포함할 수 있다.

### 5. 취소와 재개가 없다

모바일에서 700MB 다운로드는 사용자가 취소하거나 네트워크가 끊기는 상황을
일반 케이스로 봐야 한다.

필요한 개선:

- `DownloadReleaseOpts`에 `signal?: AbortSignal`을 추가한다.
- 취소 시 tmp directory와 partially downloaded artifact 처리 정책을 명확히
  한다.
- 가능하면 HTTP range/resume을 지원한다.
- 재시도 시 이미 받은 artifact를 재사용할 수 있게 한다.

### 6. Cache 상태 확인 API가 없다

reference app은 "이미 proving bundle이 준비되어 있는지"에 따라 동의 화면과
다운로드 UI를 생략하고 싶다. 현재 public API는 `downloadRelease()` 호출 전
cache hit 여부를 알기 어렵다.

필요한 개선:

- `getCachedReleaseInfo({ cacheDir, shape, expectedReleaseSha })` 같은 read-only
  API를 추가한다.
- 반환값 예시:

```ts
interface CachedReleaseInfo {
  exists: boolean;
  valid: boolean;
  stagedDir?: string;
  releaseSha?: string;
  totalBytes?: number;
}
```

### 7. 문서와 실제 구현의 차이를 정리해야 한다

`downloadRelease()` 문서는 Node와 React Native의 검증/진행률 차이를 더
명확히 설명해야 한다. 특히 production app이 `onProgress.loadedBytes`를 전체
download progress로 표시하면 안 된다는 점을 API reference에 써야 한다.

필요한 문서 수정:

- `docs/API_REFERENCE.md`
  - `loadedBytes` / `totalBytes`가 현재 artifact 기준임을 명시한다.
  - React Native는 현재 파일 완료 후 progress를 emit한다는 제한을 적는다.
  - Node와 React Native의 integrity verification 차이를 표로 정리한다.
- `docs/REACT_NATIVE_GUIDE.md`
  - 대용량 다운로드 전 사용자 동의, Wi-Fi 권장, background/cancel/retry UX를
    앱에서 처리해야 함을 적는다.
- `packages/sdk/README.md`
  - "downloadRelease and Node's loadRelease verify each artifact" 문구가
    React Native에도 동일하게 읽히지 않도록 표현을 분리한다.

## 권장 구현 순서

1. `DownloadReleaseProgress` 타입을 확장하고 기존 필드의 의미를 문서화한다.
2. React Native `downloadRelease()`에서 전체 release size를 계산해
   `releaseTotalBytes`와 `percent`를 제공한다.
3. React Native 다운로드를 progress callback 가능한 구현으로 교체한다.
4. React Native artifact SHA256 검증을 Node와 동등하게 맞춘다.
5. `AbortSignal`과 tmp cleanup/cancel 테스트를 추가한다.
6. cache status read-only API를 추가한다.
7. API reference와 React Native guide를 업데이트한다.

## 테스트 항목

- Node: chunk progress가 단조 증가하고 artifact SHA mismatch에서 실패한다.
- React Native: 큰 artifact 다운로드 중 progress가 여러 번 emit된다.
- React Native: `releaseLoadedBytes <= releaseTotalBytes`가 항상 유지된다.
- React Native: 작은 artifact 완료가 전체 `100%`로 표시되지 않는다.
- React Native: size mismatch와 SHA mismatch 모두 tmp 파일을 정리하고 실패한다.
- React Native: cached release는 추가 다운로드 없이 result를 반환한다.
- React Native: `AbortSignal` 취소 시 promise가 reject되고 partial state가
  문서화된 정책대로 처리된다.

## Reference app 임시 대응

SDK 개선 전까지 `zkap-reference-app`은 SDK raw progress를 그대로 노출하지
않는다. 앱 wrapper에서 artifact progress를 전체 proving bundle 기준으로
정규화하고, 사용자는 다운로드 전 동의/Wi-Fi 확인/진행률 UI를 본 뒤 지갑
배포를 계속한다.
