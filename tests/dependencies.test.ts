import { describe, it } from 'node:test';
import assert from 'node:assert';
import { DependencyScanner } from '../backend/scanner/dependencies/dependencyScanner';

describe('DependencyScanner Test Suite', () => {
  const scanner = new DependencyScanner();

  it('detects wildcard dependencies in package.json and parses manifests', () => {
    const pkgJsonFiles = [
      {
        path: 'package.json',
        content: JSON.stringify({
          name: 'test-app',
          dependencies: {
            express: '4.18.2',
            lodash: '*',
          },
        }),
        sizeBytes: 100,
      },
    ];
    const { findings, manifests } = scanner.scanFiles(pkgJsonFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('Wildcard') && f.filePath === 'package.json'), true);
    assert.strictEqual(manifests.length, 1);
  });

  it('detects unpinned requirements in Python requirements.txt', () => {
    const reqFiles = [
      {
        path: 'requirements.txt',
        content: 'flask\nrequests==2.28.1\ndjango',
        sizeBytes: 30,
      },
    ];
    const { findings } = scanner.scanFiles(reqFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('Unpinned') && f.snippet?.includes('flask')), true);
  });

  it('detects wildcard dependencies in Rust Cargo.toml', () => {
    const cargoFiles = [
      {
        path: 'Cargo.toml',
        content: `
        [package]
        name = "my-crate"
        version = "0.1.0"

        [dependencies]
        serde = "*"
        `,
        sizeBytes: 80,
      },
    ];
    const { findings } = scanner.scanFiles(cargoFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('Wildcard Dependency in Cargo.toml')), true);
  });

  it('matches curated CVE advisories (Lodash CVE-2021-23337 Prototype Pollution)', () => {
    const advisoryFiles = [
      {
        path: 'package.json',
        content: JSON.stringify({
          dependencies: {
            lodash: '4.17.15',
          },
        }),
        sizeBytes: 50,
      },
    ];
    const { findings } = scanner.scanFiles(advisoryFiles);
    assert.strictEqual(findings.some((f) => f.cwe?.includes('CVE-2021-23337')), true);
  });

  it('correctly uses semver matching to flag vulnerable versions and ignore safe versions', () => {
    const vulnReqs = [
      {
        path: 'requirements.txt',
        content: 'urllib3==1.26.4\nrequests==2.28.1',
        sizeBytes: 50,
      },
    ];
    const safeReqs = [
      {
        path: 'requirements.txt',
        content: 'urllib3==2.0.0\nrequests==2.31.0',
        sizeBytes: 50,
      },
    ];

    const vulnResult = scanner.scanFiles(vulnReqs);
    assert.strictEqual(
      vulnResult.findings.some((f) => f.title.includes('urllib3') && f.cwe?.includes('CVE-2021-33503')),
      true,
      'urllib3 1.26.4 should be flagged as vulnerable to CVE-2021-33503'
    );

    const safeResult = scanner.scanFiles(safeReqs);
    assert.strictEqual(
      safeResult.findings.some((f) => f.title.includes('urllib3') && f.cwe?.includes('CVE-2021-33503')),
      false,
      'urllib3 2.0.0 should NOT be flagged as vulnerable to CVE-2021-33503'
    );
  });

  it('detects vulnerabilities in pyproject.toml using semver matching', () => {
    const pyprojectFiles = [
      {
        path: 'pyproject.toml',
        content: `
        [tool.poetry.dependencies]
        python = "^3.9"
        django = "<2.2.28"
        `,
        sizeBytes: 80,
      },
    ];
    const { findings } = scanner.scanFiles(pyprojectFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('django') || f.title.includes('Django')), true);
  });

  it('detects vulnerabilities in go.mod using semver matching', () => {
    const goFiles = [
      {
        path: 'go.mod',
        content: `
        module example.com/myapp

        go 1.20

        require (
            golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
        )
        `,
        sizeBytes: 100,
      },
    ];
    const { findings } = scanner.scanFiles(goFiles);
    assert.strictEqual(findings.some((f) => f.id.includes('golang_org_x_crypto') || f.cwe?.includes('CVE-2022-27191')), true);
  });

  it('detects vulnerabilities in composer.json using semver matching', () => {
    const composerFiles = [
      {
        path: 'composer.json',
        content: JSON.stringify({
          require: {
            'guzzlehttp/guzzle': '^6.5.0',
          },
        }),
        sizeBytes: 80,
      },
    ];
    const { findings } = scanner.scanFiles(composerFiles);
    assert.strictEqual(findings.some((f) => f.id.includes('guzzlehttp_guzzle') || f.cwe?.includes('CVE-2022-31090')), true);
  });
});
