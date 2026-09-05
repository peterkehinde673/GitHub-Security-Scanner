import semver from 'semver';

/**
 * Normalizes a dependency version string from package manifests (npm, pypi, cargo, go, composer).
 */
export function normalizeDeclaredVersion(declared: string): string {
  if (!declared) return '';
  let clean = declared.trim().replace(/^["']|["']$/g, '');
  // Strip leading equals (e.g. Python ==2.28.1 or Cargo =0.10.40)
  clean = clean.replace(/^=+/g, '').trim();
  // Strip leading v/V (e.g. Go v0.0.0-...)
  clean = clean.replace(/^v/i, '').trim();
  // Normalize Python ~=2.28.0 to ~2.28.0
  clean = clean.replace(/~=/g, '~');
  // Normalize comma-separated ranges: e.g. '>=2.0.0, <2.31.0' -> '>=2.0.0 <2.31.0'
  clean = clean.replace(/,\s*/g, ' ');
  return clean;
}

/**
 * Checks whether a declared/installed dependency version satisfies any of the advisory's vulnerable version specs.
 * Uses strict semantic versioning parsing rather than simple string or package-name matching.
 *
 * @param declaredVersion The version or version constraint declared in the manifest
 * @param vulnerableSpecs Array of vulnerable version specifications (e.g. ['<4.17.21', '4.17.20'])
 */
export function isVersionVulnerable(
  declaredVersion: string,
  vulnerableSpecs: string[]
): boolean {
  if (!declaredVersion || !vulnerableSpecs || vulnerableSpecs.length === 0) {
    return false;
  }

  const cleanDecl = normalizeDeclaredVersion(declaredVersion);
  if (!cleanDecl || cleanDecl === '*' || cleanDecl === 'latest') {
    // Unbounded wildcards are flagged separately by the wildcard scanner
    return false;
  }

  // Parse declared as a concrete version (e.g. 4.17.20) or numeric coercion
  const isPureNumeric = /^\d+(\.\d+)*(-[\w.-]+)?$/.test(cleanDecl);
  const validDeclVer = semver.valid(cleanDecl) || (isPureNumeric ? semver.valid(semver.coerce(cleanDecl)) : null);

  for (const spec of vulnerableSpecs) {
    const cleanSpec = spec.trim().replace(/^["']|["']$/g, '').replace(/^v/i, '').trim();
    if (!cleanSpec) continue;

    // 1. Exact string match
    if (cleanDecl === cleanSpec) {
      return true;
    }

    const isSpecRange = /^[<>=~^]/.test(cleanSpec) || cleanSpec.includes(' ') || cleanSpec.includes('-');

    if (isSpecRange) {
      if (semver.validRange(cleanSpec)) {
        if (validDeclVer) {
          if (semver.satisfies(validDeclVer, cleanSpec, { includePrerelease: true })) {
            return true;
          }
        } else {
          const validDeclRange = semver.validRange(cleanDecl);
          if (validDeclRange && semver.intersects(validDeclRange, cleanSpec, { includePrerelease: true })) {
            return true;
          }
        }
      }
    } else {
      // Advisory spec is an exact version, e.g. '4.17.20'
      const isSpecNumeric = /^\d+(\.\d+)*(-[\w.-]+)?$/.test(cleanSpec);
      const validSpecVer = semver.valid(cleanSpec) || (isSpecNumeric ? semver.valid(semver.coerce(cleanSpec)) : null);
      if (validSpecVer) {
        if (validDeclVer) {
          if (semver.eq(validDeclVer, validSpecVer)) {
            return true;
          }
        } else {
          const validDeclRange = semver.validRange(cleanDecl);
          if (validDeclRange && semver.satisfies(validSpecVer, validDeclRange, { includePrerelease: true })) {
            return true;
          }
        }
      }
    }
  }

  return false;
}
