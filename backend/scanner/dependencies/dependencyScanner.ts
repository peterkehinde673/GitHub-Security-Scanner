import { ScannedFile, SecurityFinding, DependencyManifestSummary } from '../types';
import { KNOWN_ADVISORIES } from './advisories';
import { isVersionVulnerable } from './semverMatcher';

export class DependencyScanner {
  /**
   * Scans dependency manifest files across standard package ecosystems (npm, pypi, cargo, go, rubygems, composer).
   * Note: This audit is performed strictly by static text/JSON parsing; NO package managers (npm, pip, cargo, etc.) are executed.
   */
  public scanFiles(files: ScannedFile[]): {
    findings: SecurityFinding[];
    manifests: DependencyManifestSummary[];
  } {
    const findings: SecurityFinding[] = [];
    const manifests: DependencyManifestSummary[] = [];

    for (const file of files) {
      const fileName = file.path.split('/').pop() || file.path;

      if (fileName === 'package.json') {
        const result = this.scanPackageJson(file);
        findings.push(...result.findings);
        if (result.manifest) manifests.push(result.manifest);
      } else if (fileName === 'requirements.txt') {
        const result = this.scanRequirementsTxt(file);
        findings.push(...result.findings);
        if (result.manifest) manifests.push(result.manifest);
      } else if (fileName === 'pyproject.toml') {
        const result = this.scanPyprojectToml(file);
        findings.push(...result.findings);
        if (result.manifest) manifests.push(result.manifest);
      } else if (fileName === 'Cargo.toml') {
        const result = this.scanCargoToml(file);
        findings.push(...result.findings);
        if (result.manifest) manifests.push(result.manifest);
      } else if (fileName === 'go.mod') {
        const result = this.scanGoMod(file);
        findings.push(...result.findings);
        if (result.manifest) manifests.push(result.manifest);
      } else if (fileName === 'composer.json') {
        const result = this.scanComposerJson(file);
        findings.push(...result.findings);
        if (result.manifest) manifests.push(result.manifest);
      } else if (fileName === 'Gemfile') {
        const result = this.scanGemfile(file);
        findings.push(...result.findings);
        if (result.manifest) manifests.push(result.manifest);
      }
    }

    return { findings, manifests };
  }

  // 1. package.json (npm)
  private scanPackageJson(file: ScannedFile): {
    findings: SecurityFinding[];
    manifest: DependencyManifestSummary | null;
  } {
    const findings: SecurityFinding[] = [];
    let totalDeps = 0;
    let flaggedDeps = 0;

    try {
      const json = JSON.parse(file.content);
      const allDeps = {
        ...(json.dependencies || {}),
        ...(json.devDependencies || {}),
      };

      const lines = file.content.split('\n');

      for (const [pkg, ver] of Object.entries(allDeps)) {
        totalDeps++;
        const versionStr = String(ver).trim();

        // Check wildcard
        if (versionStr === '*' || versionStr === 'latest' || versionStr === '' || versionStr === '^') {
          flaggedDeps++;
          const lineIdx = lines.findIndex((l) => l.includes(`"${pkg}"`));
          const startLine = lineIdx !== -1 ? lineIdx + 1 : 1;

          findings.push({
            id: `dep-npm-wildcard-${pkg}-${startLine}`,
            category: 'DEPENDENCIES',
            severity: 'HIGH',
            title: `Wildcard / Unpinned Dependency: ${pkg}@${versionStr}`,
            description: `The dependency "${pkg}" uses a wildcard or unpinned range "${versionStr}", allowing untrusted breaking versions or malicious supply chain injections during fresh installs.`,
            impact: 'Supply-chain tampering, non-reproducible builds, and automatic pull-in of compromised packages.',
            recommendation: `Pin "${pkg}" to a specific, vetted semantic version range (e.g. "^1.2.3").`,
            filePath: file.path,
            startLine,
            endLine: startLine,
            cwe: 'CWE-1104: Use of Unmaintained or Untrusted Third-Party Components',
            confidence: 'HIGH',
            snippet: lines[lineIdx] || `"${pkg}": "${versionStr}"`,
            remediationSnippet: `"${pkg}": "^1.0.0"`,
          });
        }

        // Check curated advisories with semver range evaluation
        const advisory = KNOWN_ADVISORIES.find((a) => a.packageName === pkg && a.ecosystem === 'npm');
        if (advisory && isVersionVulnerable(versionStr, advisory.vulnerableVersions)) {
          flaggedDeps++;
          const lineIdx = lines.findIndex((l) => l.includes(`"${pkg}"`));
          const startLine = lineIdx !== -1 ? lineIdx + 1 : 1;

          findings.push({
            id: `dep-npm-advisory-${pkg}-${startLine}`,
            category: 'DEPENDENCIES',
            severity: advisory.severity,
            title: advisory.title,
            description: `${advisory.description} (Audited against curated high-priority security advisory dataset)`,
            impact: 'Known published vulnerability exploitation against application runtime.',
            recommendation: advisory.recommendation,
            filePath: file.path,
            startLine,
            endLine: startLine,
            cwe: advisory.cve,
            confidence: 'HIGH',
            snippet: lines[lineIdx] || `"${pkg}": "${versionStr}"`,
          });
        }
      }

      return {
        findings,
        manifest: {
          manifestPath: file.path,
          ecosystem: 'npm (Node.js)',
          totalDependencies: totalDeps,
          flaggedDependencies: flaggedDeps,
        },
      };
    } catch {
      return { findings: [], manifest: null };
    }
  }

  // 2. requirements.txt (Python)
  private scanRequirementsTxt(file: ScannedFile): {
    findings: SecurityFinding[];
    manifest: DependencyManifestSummary | null;
  } {
    const findings: SecurityFinding[] = [];
    const lines = file.content.split('\n');
    let totalDeps = 0;
    let flaggedDeps = 0;

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-r') || trimmed.startsWith('-i')) return;

      totalDeps++;
      const pkgName = trimmed.split(/[=<>~]/)[0].trim();

      // Check unpinned
      if (!trimmed.includes('==') && !trimmed.includes('>=') && !trimmed.includes('~=') && !trimmed.includes('<=')) {
        flaggedDeps++;
        findings.push({
          id: `dep-pypi-unpinned-${idx + 1}`,
          category: 'DEPENDENCIES',
          severity: 'MEDIUM',
          title: `Unpinned Python Requirement: ${pkgName}`,
          description: `The package "${pkgName}" has no version constraint in requirements.txt, making builds non-deterministic and susceptible to malicious upstream updates.`,
          impact: 'Supply-chain dependency confusion and unverified remote library updates.',
          recommendation: `Pin with explicit version equality: ${pkgName}==<version>`,
          filePath: file.path,
          startLine: idx + 1,
          endLine: idx + 1,
          cwe: 'CWE-1104: Use of Unmaintained Component',
          confidence: 'HIGH',
          snippet: line,
          remediationSnippet: `${pkgName}==1.0.0`,
        });
      }

      // Check curated advisories with semver range evaluation
      const advisory = KNOWN_ADVISORIES.find((a) => a.packageName.toLowerCase() === pkgName.toLowerCase() && a.ecosystem === 'pypi');
      const versionSpec = trimmed.slice(pkgName.length).trim();
      if (advisory && isVersionVulnerable(versionSpec, advisory.vulnerableVersions)) {
        flaggedDeps++;
        findings.push({
          id: `dep-pypi-advisory-${pkgName}-${idx + 1}`,
          category: 'DEPENDENCIES',
          severity: advisory.severity,
          title: advisory.title,
          description: `${advisory.description} (Audited against curated high-priority security advisory dataset)`,
          impact: 'Known published vulnerability exploitation against application runtime.',
          recommendation: advisory.recommendation,
          filePath: file.path,
          startLine: idx + 1,
          endLine: idx + 1,
          cwe: advisory.cve,
          confidence: 'HIGH',
          snippet: line,
        });
      }
    });

    return {
      findings,
      manifest: {
        manifestPath: file.path,
        ecosystem: 'pypi (Python)',
        totalDependencies: totalDeps,
        flaggedDependencies: flaggedDeps,
      },
    };
  }

  // 3. pyproject.toml (Python Poetry / PEP 621)
  private scanPyprojectToml(file: ScannedFile): {
    findings: SecurityFinding[];
    manifest: DependencyManifestSummary | null;
  } {
    const findings: SecurityFinding[] = [];
    const lines = file.content.split('\n');
    let totalDeps = 0;
    let flaggedDeps = 0;
    let inDepsSection = false;

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('[tool.poetry.dependencies]') || trimmed.startsWith('[project.dependencies]')) {
        inDepsSection = true;
        return;
      }
      if (inDepsSection && trimmed.startsWith('[')) {
        inDepsSection = false;
        return;
      }

      if (inDepsSection && trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
        totalDeps++;
        const parts = trimmed.split('=');
        const pkg = parts[0].trim().replace(/^["']|["']$/g, '');
        const ver = parts[1].trim().replace(/^["']|["']$/g, '');

        if (ver === '*' || ver === '') {
          flaggedDeps++;
          findings.push({
            id: `dep-pyproject-wildcard-${pkg}-${idx + 1}`,
            category: 'DEPENDENCIES',
            severity: 'HIGH',
            title: `Wildcard Dependency in pyproject.toml: ${pkg}`,
            description: `The package "${pkg}" specifies wildcard version "*", permitting unvetted upstream releases.`,
            impact: 'Non-reproducible builds and supply chain injection.',
            recommendation: `Specify a pinned version constraint: ${pkg} = "^1.0.0"`,
            filePath: file.path,
            startLine: idx + 1,
            endLine: idx + 1,
            cwe: 'CWE-1104: Use of Unmaintained Component',
            confidence: 'HIGH',
            snippet: line,
          });
        }

        const advisory = KNOWN_ADVISORIES.find(
          (a) => a.packageName.toLowerCase() === pkg.toLowerCase() && a.ecosystem === 'pypi'
        );
        if (advisory && isVersionVulnerable(ver, advisory.vulnerableVersions)) {
          flaggedDeps++;
          findings.push({
            id: `dep-pyproject-advisory-${pkg}-${idx + 1}`,
            category: 'DEPENDENCIES',
            severity: advisory.severity,
            title: advisory.title,
            description: advisory.description,
            impact: 'Known vulnerability in Python dependency.',
            recommendation: advisory.recommendation,
            filePath: file.path,
            startLine: idx + 1,
            endLine: idx + 1,
            cwe: advisory.cve,
            confidence: 'HIGH',
            snippet: line,
          });
        }
      }
    });

    return {
      findings,
      manifest: {
        manifestPath: file.path,
        ecosystem: 'pyproject.toml (Python)',
        totalDependencies: totalDeps,
        flaggedDependencies: flaggedDeps,
      },
    };
  }

  // 4. Cargo.toml (Rust)
  private scanCargoToml(file: ScannedFile): {
    findings: SecurityFinding[];
    manifest: DependencyManifestSummary | null;
  } {
    const findings: SecurityFinding[] = [];
    const lines = file.content.split('\n');
    let totalDeps = 0;
    let flaggedDeps = 0;
    let inDepsSection = false;

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('[dependencies]') || trimmed.startsWith('[dev-dependencies]')) {
        inDepsSection = true;
        return;
      }
      if (inDepsSection && trimmed.startsWith('[')) {
        inDepsSection = false;
        return;
      }

      if (inDepsSection && trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
        totalDeps++;
        const parts = trimmed.split('=');
        const crate = parts[0].trim().replace(/^["']|["']$/g, '');
        const ver = parts[1].trim().replace(/^["']|["']$/g, '');

        if (ver === '"*"' || ver === "'*'" || ver === '*') {
          flaggedDeps++;
          findings.push({
            id: `dep-cargo-wildcard-${crate}-${idx + 1}`,
            category: 'DEPENDENCIES',
            severity: 'HIGH',
            title: `Wildcard Dependency in Cargo.toml: ${crate}`,
            description: `The crate "${crate}" specifies wildcard version "*". Cargo requires explicit semver ranges for reproducible and safe compilation.`,
            impact: 'Breaking builds and supply chain injection.',
            recommendation: `Pin crate version: ${crate} = "1.0"`,
            filePath: file.path,
            startLine: idx + 1,
            endLine: idx + 1,
            cwe: 'CWE-1104: Use of Unmaintained Component',
            confidence: 'HIGH',
            snippet: line,
          });
        }

        const advisory = KNOWN_ADVISORIES.find((a) => a.packageName === crate && a.ecosystem === 'crates');
        if (advisory && isVersionVulnerable(ver, advisory.vulnerableVersions)) {
          flaggedDeps++;
          findings.push({
            id: `dep-cargo-advisory-${crate}-${idx + 1}`,
            category: 'DEPENDENCIES',
            severity: advisory.severity,
            title: advisory.title,
            description: advisory.description,
            impact: 'Known vulnerability in crate dependency.',
            recommendation: advisory.recommendation,
            filePath: file.path,
            startLine: idx + 1,
            endLine: idx + 1,
            cwe: advisory.cve,
            confidence: 'HIGH',
            snippet: line,
          });
        }
      }
    });

    return {
      findings,
      manifest: {
        manifestPath: file.path,
        ecosystem: 'Cargo (Rust)',
        totalDependencies: totalDeps,
        flaggedDependencies: flaggedDeps,
      },
    };
  }

  // 5. go.mod (Go)
  private scanGoMod(file: ScannedFile): {
    findings: SecurityFinding[];
    manifest: DependencyManifestSummary | null;
  } {
    const findings: SecurityFinding[] = [];
    const lines = file.content.split('\n');
    let totalDeps = 0;
    let flaggedDeps = 0;
    let inRequire = false;

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('require (')) {
        inRequire = true;
        return;
      }
      if (inRequire && trimmed.startsWith(')')) {
        inRequire = false;
        return;
      }

      if ((inRequire || trimmed.startsWith('require ')) && trimmed && !trimmed.startsWith('//')) {
        totalDeps++;
        const modPart = trimmed.replace(/^require\s+/, '').trim();
        const [modPath, modVer] = modPart.split(/\s+/);

        const advisory = KNOWN_ADVISORIES.find(
          (a) => a.packageName.toLowerCase() === modPath.toLowerCase() && a.ecosystem === 'go'
        );
        if (advisory && modVer && isVersionVulnerable(modVer, advisory.vulnerableVersions)) {
          flaggedDeps++;
          findings.push({
            id: `dep-go-advisory-${modPath.replace(/[^a-zA-Z0-9]/g, '_')}-${idx + 1}`,
            category: 'DEPENDENCIES',
            severity: advisory.severity,
            title: advisory.title,
            description: advisory.description,
            impact: 'Vulnerability in Go module dependency.',
            recommendation: advisory.recommendation,
            filePath: file.path,
            startLine: idx + 1,
            endLine: idx + 1,
            cwe: advisory.cve,
            cvssScore: advisory.severity === 'CRITICAL' ? 9.8 : advisory.severity === 'HIGH' ? 8.2 : 5.5,
            confidence: 'HIGH',
            snippet: line,
            vulnerableSnippet: line,
            fixedSnippet: `// Update ${modPath} in go.mod\n${advisory.recommendation}`,
            maskedSnippet: line,
            remediationSnippet: `// Update ${modPath} in go.mod\n${advisory.recommendation}`,
          });
        }
      }
    });

    return {
      findings,
      manifest: {
        manifestPath: file.path,
        ecosystem: 'go.mod (Go)',
        totalDependencies: totalDeps,
        flaggedDependencies: flaggedDeps,
      },
    };
  }

  // 6. composer.json (PHP)
  private scanComposerJson(file: ScannedFile): {
    findings: SecurityFinding[];
    manifest: DependencyManifestSummary | null;
  } {
    const findings: SecurityFinding[] = [];
    let totalDeps = 0;
    let flaggedDeps = 0;

    try {
      const json = JSON.parse(file.content);
      const reqs = { ...(json.require || {}), ...(json['require-dev'] || {}) };
      const lines = file.content.split('\n');

      for (const [pkg, ver] of Object.entries(reqs)) {
        if (pkg === 'php') continue;
        totalDeps++;
        const advisory = KNOWN_ADVISORIES.find(
          (a) => a.packageName.toLowerCase() === pkg.toLowerCase() && a.ecosystem === 'composer'
        );
        if (advisory && isVersionVulnerable(String(ver), advisory.vulnerableVersions)) {
          flaggedDeps++;
          const lineIdx = lines.findIndex((l) => l.includes(`"${pkg}"`));
          const startLine = lineIdx !== -1 ? lineIdx + 1 : 1;

          findings.push({
            id: `dep-composer-advisory-${pkg.replace(/[^a-zA-Z0-9]/g, '_')}-${startLine}`,
            category: 'DEPENDENCIES',
            severity: advisory.severity,
            title: advisory.title,
            description: advisory.description,
            impact: 'Vulnerable PHP dependency.',
            recommendation: advisory.recommendation,
            filePath: file.path,
            startLine,
            endLine: startLine,
            cwe: advisory.cve,
            cvssScore: advisory.severity === 'CRITICAL' ? 9.8 : advisory.severity === 'HIGH' ? 8.2 : 5.5,
            confidence: 'HIGH',
            snippet: lines[lineIdx] || `"${pkg}": "${ver}"`,
            vulnerableSnippet: lines[lineIdx] || `"${pkg}": "${ver}"`,
            fixedSnippet: `"${pkg}": "^vetted_version"`,
            maskedSnippet: lines[lineIdx] || `"${pkg}": "${ver}"`,
            remediationSnippet: `"${pkg}": "^vetted_version"`,
          });
        }
      }

      return {
        findings,
        manifest: {
          manifestPath: file.path,
          ecosystem: 'Composer (PHP)',
          totalDependencies: totalDeps,
          flaggedDependencies: flaggedDeps,
        },
      };
    } catch {
      return { findings: [], manifest: null };
    }
  }

  // 7. Gemfile (Ruby)
  private scanGemfile(file: ScannedFile): {
    findings: SecurityFinding[];
    manifest: DependencyManifestSummary | null;
  } {
    const findings: SecurityFinding[] = [];
    const lines = file.content.split('\n');
    let totalDeps = 0;
    let flaggedDeps = 0;

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('gem ') || trimmed.startsWith('gem(')) {
        totalDeps++;
        // Check if unpinned
        if (!trimmed.includes(',') && !trimmed.includes('~>') && !trimmed.includes('>=') && !trimmed.includes('==')) {
          flaggedDeps++;
          const gemName = trimmed.replace(/^gem\s*\(?['"]([^'"]+)['"].*/, '$1');
          findings.push({
            id: `dep-gem-unpinned-${idx + 1}`,
            category: 'DEPENDENCIES',
            severity: 'MEDIUM',
            title: `Unpinned Ruby Gem: ${gemName}`,
            description: `The gem "${gemName}" in Gemfile has no version constraint specified.`,
            impact: 'Non-reproducible bundle installations and untrusted updates.',
            recommendation: `Specify version constraint: gem '${gemName}', '~> 1.0'`,
            filePath: file.path,
            startLine: idx + 1,
            endLine: idx + 1,
            cwe: 'CWE-1104: Use of Unmaintained Component',
            confidence: 'HIGH',
            snippet: line,
          });
        }
      }
    });

    return {
      findings,
      manifest: {
        manifestPath: file.path,
        ecosystem: 'Gemfile (Ruby)',
        totalDependencies: totalDeps,
        flaggedDependencies: flaggedDeps,
      },
    };
  }
}
