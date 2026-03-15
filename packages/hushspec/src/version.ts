/** Current HushSpec specification version. */
export const HUSHSPEC_VERSION = '0.1.0';

/** All supported HushSpec specification versions. */
export const SUPPORTED_VERSIONS = ['0.1.0'] as const;

/** Returns true if the given version string is supported. */
export function isSupported(version: string): boolean {
  return (SUPPORTED_VERSIONS as readonly string[]).includes(version);
}
