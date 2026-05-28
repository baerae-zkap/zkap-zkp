export class UnsupportedPlatformError extends Error {
  readonly api: string;
  readonly platform: string;

  constructor(api: string, platform: string, message?: string) {
    super(
      message ??
        `[zkap-zkp] ${api} is not supported in the ${platform} runtime.`,
    );
    this.name = 'UnsupportedPlatformError';
    this.api = api;
    this.platform = platform;
  }
}
