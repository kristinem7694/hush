export const HUSHSPEC_VERSION = '0.1.0';
export const SUPPORTED_VERSIONS = ['0.1.0'] as const;

export function isSupported(version: string): boolean {
  return (SUPPORTED_VERSIONS as readonly string[]).includes(version);
}
