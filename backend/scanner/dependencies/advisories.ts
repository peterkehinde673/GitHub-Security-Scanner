import { Severity } from '../types';

export interface KnownAdvisory {
  packageName: string;
  ecosystem: 'npm' | 'pypi' | 'crates' | 'go' | 'rubygems' | 'composer';
  vulnerableVersions: string[];
  cve: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
}

export const KNOWN_ADVISORIES: KnownAdvisory[] = [
  // NPM
  {
    packageName: 'lodash',
    ecosystem: 'npm',
    vulnerableVersions: ['4.17.20', '4.17.19', '4.17.15', '<4.17.21'],
    cve: 'CVE-2021-23337: Lodash Command Injection',
    severity: 'HIGH',
    title: 'Vulnerable Lodash Version (CVE-2021-23337)',
    description: 'Versions of lodash prior to 4.17.21 are vulnerable to Command Injection via template functions.',
    recommendation: 'Upgrade lodash to version 4.17.21 or later.',
  },
  {
    packageName: 'express',
    ecosystem: 'npm',
    vulnerableVersions: ['<4.18.0'],
    cve: 'CVE-2022-24999: Express qs Prototype Pollution',
    severity: 'HIGH',
    title: 'Outdated Express Dependency with qs Prototype Pollution',
    description: 'Express versions prior to 4.18.0 contain a vulnerable qs subdependency prone to prototype pollution.',
    recommendation: 'Upgrade express to ^4.18.2 or ^4.21.0.',
  },
  {
    packageName: 'axios',
    ecosystem: 'npm',
    vulnerableVersions: ['<0.21.2', '0.21.1', '0.21.0'],
    cve: 'CVE-2021-3749: Axios SSRF via relative URL follow-redirects',
    severity: 'HIGH',
    title: 'Axios Vulnerability (CVE-2021-3749)',
    description: 'Axios versions before 0.21.2 contain a vulnerability leading to SSRF and credential leak when following redirects.',
    recommendation: 'Upgrade axios to version >= 1.6.0.',
  },
  {
    packageName: 'jsonwebtoken',
    ecosystem: 'npm',
    vulnerableVersions: ['<9.0.0', '8.5.1', '8.5.0'],
    cve: 'CVE-2022-23529: Insecure Key Handling RCE',
    severity: 'CRITICAL',
    title: 'JsonWebToken Arbitrary File Write / RCE (CVE-2022-23529)',
    description: 'jsonwebtoken library before 9.0.0 is vulnerable to arbitrary code execution if secretOrPublicKey is untrusted.',
    recommendation: 'Upgrade jsonwebtoken to >= 9.0.0.',
  },
  // PyPI
  {
    packageName: 'flask',
    ecosystem: 'pypi',
    vulnerableVersions: ['<2.0.0'],
    cve: 'CVE-2018-1000656: Flask Session Cookie Crafting',
    severity: 'HIGH',
    title: 'Outdated Flask Package with Cookie Crafting Vulnerability',
    description: 'Flask versions before 2.0.0 have vulnerabilities with insecure default session handling.',
    recommendation: 'Pin flask to >=2.2.5 or latest 3.x.',
  },
  {
    packageName: 'requests',
    ecosystem: 'pypi',
    vulnerableVersions: ['<2.31.0'],
    cve: 'CVE-2023-32681: Requests Unintended Proxy-Authorization Header Leak',
    severity: 'MEDIUM',
    title: 'Requests Proxy Header Leak (CVE-2023-32681)',
    description: 'Requests leaks Proxy-Authorization header to destination servers when following redirects.',
    recommendation: 'Upgrade requests to >= 2.31.0.',
  },
  {
    packageName: 'django',
    ecosystem: 'pypi',
    vulnerableVersions: ['<4.2.11', '<3.2.25'],
    cve: 'CVE-2024-27351: Django Potential ReDoS in django.utils.text.Truncator',
    severity: 'HIGH',
    title: 'Django Regular Expression Denial of Service (CVE-2024-27351)',
    description: 'Unpatched Django releases allow remote attackers to cause denial of service via long strings.',
    recommendation: 'Upgrade Django to >= 4.2.11 or latest 5.x.',
  },
  {
    packageName: 'urllib3',
    ecosystem: 'pypi',
    vulnerableVersions: ['>=1.25.4 <1.26.5'],
    cve: 'CVE-2021-33503: urllib3 Catastrophic ReDoS in URL authority parsing',
    severity: 'HIGH',
    title: 'urllib3 Regular Expression Denial of Service (CVE-2021-33503)',
    description: 'urllib3 before 1.26.5 allows remote attackers to cause denial of service via catastrophic regex backtracking.',
    recommendation: 'Upgrade urllib3 to >= 1.26.5.',
  },
  // Rust Crates
  {
    packageName: 'openssl',
    ecosystem: 'crates',
    vulnerableVersions: ['<0.10.48'],
    cve: 'CVE-2022-2068: OpenSSL c_rehash script command injection',
    severity: 'HIGH',
    title: 'Vulnerable OpenSSL Crate Binding',
    description: 'Older crate versions contain security vulnerabilities in underlying OpenSSL bindings.',
    recommendation: 'Upgrade openssl crate to >= 0.10.48.',
  },
  // Go
  {
    packageName: 'golang.org/x/crypto',
    ecosystem: 'go',
    vulnerableVersions: ['<0.0.0-20220315160706-3147a52a75dd'],
    cve: 'CVE-2022-27191: Go Crypto Crash on empty public key',
    severity: 'HIGH',
    title: 'Go Crypto SSH / Curve Crash Vulnerability',
    description: 'Vulnerability in golang.org/x/crypto/ssh allows remote unauthenticated denial of service.',
    recommendation: 'Upgrade golang.org/x/crypto to latest module version.',
  },
  // PHP Composer
  {
    packageName: 'guzzlehttp/guzzle',
    ecosystem: 'composer',
    vulnerableVersions: ['<7.4.5'],
    cve: 'CVE-2022-31090: Guzzle CORS and Authorization Header Leak',
    severity: 'HIGH',
    title: 'Guzzle HTTP Client Authorization Header Leak',
    description: 'Guzzle forwards Authorization headers on redirect to untrusted hosts.',
    recommendation: 'Upgrade guzzlehttp/guzzle to >= 7.4.5.',
  },
];
