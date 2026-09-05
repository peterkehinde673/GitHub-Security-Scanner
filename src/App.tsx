import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { RepoInputBar } from './components/RepoInputBar';
import { SecurityScoreOverview } from './components/SecurityScoreOverview';
import { VulnerabilitiesList } from './components/VulnerabilitiesList';
import { IssueInspector } from './components/IssueInspector';
import { CodeWorkspace } from './components/CodeWorkspace';
import { AiSecurityChatDrawer } from './components/AiSecurityChatDrawer';
import { AuditReportExportModal } from './components/AuditReportExportModal';
import { SAMPLE_SCENARIOS, SampleScenario } from './data/sampleSnippets';
import { ScanResult, SecurityIssue, CodeFile } from './types';
import { ShieldCheck, Code, Layers, AlertTriangle, Sparkles } from 'lucide-react';

export function App() {
  const [activeTargetName, setActiveTargetName] = useState<string>('Node/Express Auth API (Sample)');
  const [workspaceFiles, setWorkspaceFiles] = useState<CodeFile[]>([
    {
      path: SAMPLE_SCENARIOS[0].filename,
      content: SAMPLE_SCENARIOS[0].code,
    },
  ]);
  const [activeFileIndex, setActiveFileIndex] = useState<number>(0);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [selectedIssue, setSelectedIssue] = useState<SecurityIssue | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [viewMode, setViewMode] = useState<'overview' | 'code'>('overview');
  const [isAiChatOpen, setIsAiChatOpen] = useState<boolean>(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string>('');

  // Initial auto-scan of default scenario on mount
  useEffect(() => {
    executeScan(workspaceFiles, SAMPLE_SCENARIOS[0].name, 'SNIPPET');
  }, []);

  const executeScan = async (
    files: CodeFile[],
    targetName: string,
    targetType: 'REPO' | 'SNIPPET' | 'FILES',
    coverage?: any
  ) => {
    setIsScanning(true);
    setErrorMessage('');
    setStatusMessage('Auditing pattern-based SAST, evaluating security rules, and generating remediation patches...');

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetName,
          targetType,
          files,
          coverage,
        }),
      });

      const data = await res.json().catch(() => ({ error: 'Security scan failed to return valid JSON output.' }));

      if (!res.ok) {
        throw new Error(data.error || 'Scan failed to execute properly');
      }

      setScanResult(data);
      if (data.issues && data.issues.length > 0) {
        setSelectedIssue(data.issues[0]);
      } else {
        setSelectedIssue(null);
      }
    } catch (err: any) {
      console.error('Scan error:', err);
      setErrorMessage(`Security scan error: ${err.message}`);
    } finally {
      setIsScanning(false);
      setStatusMessage('');
    }
  };

  const handleScanRepo = async (repoQuery: string) => {
    setIsScanning(true);
    setErrorMessage('');
    setStatusMessage(`Connecting to GitHub API for ${repoQuery}...`);

    try {
      // 1. Clean and validate repository identifier
      const cleanRepo = repoQuery
        .trim()
        .replace(/^https?:\/\/github\.com\//i, '')
        .replace(/^\/+/, '')
        .replace(/\/+$/, '')
        .replace(/\.git$/i, '');

      if (!cleanRepo || !cleanRepo.includes('/')) {
        throw new Error('Please provide a repository in "owner/repo" format (e.g. expressjs/express) or a full GitHub URL.');
      }

      const infoRes = await fetch(`/api/github/repo-info?repo=${encodeURIComponent(cleanRepo)}`);
      const repoInfo = await infoRes.json().catch(() => ({ error: 'Failed to contact GitHub API.' }));
      
      if (!infoRes.ok) {
        throw new Error(repoInfo.error || 'Failed to fetch GitHub repository');
      }

      setStatusMessage(`Fetching repository files from ${repoInfo.fullName} (branch: ${repoInfo.defaultBranch})...`);

      // 2. Fetch code files with bounded concurrency and size limits
      const filesRes = await fetch('/api/github/fetch-files', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoFullName: repoInfo.fullName,
          branch: repoInfo.defaultBranch,
          maxFiles: 25,
        }),
      });

      const filesData = await filesRes.json().catch(() => ({ error: 'Failed to retrieve repository files from GitHub.' }));

      if (!filesRes.ok) {
        throw new Error(filesData.error || 'Failed to fetch code files from GitHub');
      }

      if (!filesData.files || filesData.files.length === 0) {
        throw new Error('No supported code or configuration files found in this repository.');
      }

      setWorkspaceFiles(filesData.files);
      setActiveFileIndex(0);
      setActiveTargetName(repoInfo.fullName);

      // 3. Scan the fetched files while forwarding coverage metadata
      await executeScan(filesData.files, repoInfo.fullName, 'REPO', filesData.coverage);
    } catch (err: any) {
      setErrorMessage(`GitHub Repository Scan Error: ${err.message}`);
    } finally {
      setIsScanning(false);
      setStatusMessage('');
    }
  };

  const handleSelectSample = (scenario: SampleScenario) => {
    const files: CodeFile[] = [
      {
        path: scenario.filename,
        content: scenario.code,
      },
    ];
    setWorkspaceFiles(files);
    setActiveFileIndex(0);
    setActiveTargetName(scenario.name);
    executeScan(files, scenario.name, 'SNIPPET');
  };

  const handleUploadFiles = (files: CodeFile[]) => {
    setWorkspaceFiles(files);
    setActiveFileIndex(0);
    const targetName = `Uploaded Project (${files.length} files)`;
    setActiveTargetName(targetName);
    executeScan(files, targetName, 'FILES');
  };

  const handleCustomCodeScan = (code: string, filename: string) => {
    const files: CodeFile[] = [{ path: filename, content: code }];
    setWorkspaceFiles(files);
    setActiveFileIndex(0);
    const targetName = `Custom Snippet (${filename})`;
    setActiveTargetName(targetName);
    executeScan(files, targetName, 'SNIPPET');
  };

  const handleUpdateFileContent = (idx: number, newContent: string) => {
    setWorkspaceFiles((prev) => {
      const updated = [...prev];
      if (updated[idx]) {
        updated[idx] = { ...updated[idx], content: newContent };
      }
      return updated;
    });
  };

  const handleTriggerRescan = () => {
    executeScan(workspaceFiles, activeTargetName, 'SNIPPET');
  };

  const handleApplyFix = (issueId: string) => {
    if (!scanResult) return;

    const targetIssue = scanResult.issues.find((i) => i.id === issueId);
    if (!targetIssue || !targetIssue.fixedSnippet) return;

    // Apply fix to workspace file
    const fileIndex = workspaceFiles.findIndex(
      (f) => f.path === targetIssue.filePath || f.path.endsWith(targetIssue.filePath)
    );

    if (fileIndex !== -1) {
      const currentFile = workspaceFiles[fileIndex];
      let newContent = currentFile.content;

      if (targetIssue.vulnerableSnippet && newContent.includes(targetIssue.vulnerableSnippet)) {
        newContent = newContent.replace(targetIssue.vulnerableSnippet, targetIssue.fixedSnippet);
      } else {
        // Replace around the specific line number
        const lines = newContent.split('\n');
        const startIdx = Math.max(0, targetIssue.startLine - 1);
        const endIdx = Math.min(lines.length - 1, targetIssue.endLine - 1);
        lines.splice(startIdx, endIdx - startIdx + 1, targetIssue.fixedSnippet);
        newContent = lines.join('\n');
      }

      handleUpdateFileContent(fileIndex, newContent);

      // Update scanResult state to mark as applied
      setScanResult((prev) => {
        if (!prev) return null;
        const updatedIssues = prev.issues.map((i) =>
          i.id === issueId ? { ...i, applied: true } : i
        );

        return {
          ...prev,
          issues: updatedIssues,
        };
      });

      if (selectedIssue?.id === issueId) {
        setSelectedIssue((prev) => (prev ? { ...prev, applied: true } : null));
      }
    }
  };

  const handleAskAi = (issue: SecurityIssue) => {
    setSelectedIssue(issue);
    setIsAiChatOpen(true);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-blue-600 selection:text-white">
      <Header
        scanResult={scanResult}
        isScanning={isScanning}
        onOpenReportModal={() => setIsReportModalOpen(true)}
        onOpenAiChat={() => setIsAiChatOpen(true)}
        onResetScan={() => handleSelectSample(SAMPLE_SCENARIOS[0])}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 lg:p-8">
        {/* Input Target Configuration Bar */}
        <RepoInputBar
          onScanRepo={handleScanRepo}
          onSelectSample={handleSelectSample}
          onUploadFiles={handleUploadFiles}
          onCustomCodeScan={handleCustomCodeScan}
          isScanning={isScanning}
          activeTargetName={activeTargetName}
        />

        {/* Loading Progress Bar */}
        {isScanning && (
          <div className="bg-slate-900 border border-blue-500/40 rounded-xl p-4 mb-6 flex items-center gap-3 shadow-lg animate-pulse">
            <div className="w-5 h-5 border-2 border-blue-400 border-t-transparent rounded-full animate-spin shrink-0" />
            <span className="text-xs sm:text-sm text-blue-300 font-medium">
              {statusMessage || 'Analyzing security vulnerabilities, detecting secrets, and calculating metrics...'}
            </span>
          </div>
        )}

        {/* In-app Error Banner */}
        {errorMessage && (
          <div className="bg-red-950/60 border border-red-800/80 rounded-xl p-4 mb-6 flex items-center justify-between gap-3 shadow-lg text-red-200">
            <div className="flex items-center gap-2 text-xs sm:text-sm">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{errorMessage}</span>
            </div>
            <button
              onClick={() => setErrorMessage('')}
              className="text-xs px-2.5 py-1 rounded-lg bg-red-900/60 hover:bg-red-800 text-red-100 font-medium transition-colors cursor-pointer shrink-0"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Scan Results View */}
        {scanResult && (
          <div>
            {/* Score & Executive Summary */}
            <SecurityScoreOverview scanResult={scanResult} />

            {/* View Switcher Tabs */}
            <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-3 mb-5">
              <div className="flex items-center gap-2">
                <button
                  id="tab-view-overview"
                  onClick={() => setViewMode('overview')}
                  className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
                    viewMode === 'overview'
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  <Layers className="w-3.5 h-3.5" />
                  <span>Vulnerability Inspector</span>
                </button>

                <button
                  id="tab-view-code"
                  onClick={() => setViewMode('code')}
                  className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
                    viewMode === 'code'
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  <Code className="w-3.5 h-3.5" />
                  <span>Interactive Code Workspace ({workspaceFiles.length} files)</span>
                </button>
              </div>

              <div className="hidden sm:flex items-center gap-2 text-xs text-slate-400">
                <span>Findings:</span>
                <span className="font-bold text-slate-200">{scanResult.issues.length}</span>
              </div>
            </div>

            {/* View Mode 1: Vulnerabilities List + Deep Inspector */}
            {viewMode === 'overview' ? (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
                <div className="lg:col-span-6">
                  <VulnerabilitiesList
                    issues={scanResult.issues}
                    selectedIssue={selectedIssue}
                    onSelectIssue={(issue) => setSelectedIssue(issue)}
                    onApplyFix={handleApplyFix}
                  />
                </div>

                <div className="lg:col-span-6 sticky top-20">
                  <IssueInspector
                    issue={selectedIssue}
                    onApplyFix={handleApplyFix}
                    onAskAi={handleAskAi}
                    onClose={() => setSelectedIssue(null)}
                  />
                </div>
              </div>
            ) : (
              /* View Mode 2: Multi-file Code Workspace with highlighted issues */
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
                <div className="lg:col-span-8">
                  <CodeWorkspace
                    files={workspaceFiles}
                    issues={scanResult.issues}
                    activeFileIndex={activeFileIndex}
                    onSelectFileIndex={setActiveFileIndex}
                    onUpdateFileContent={handleUpdateFileContent}
                    onTriggerRescan={handleTriggerRescan}
                    isScanning={isScanning}
                    onSelectIssue={(issue) => {
                      setSelectedIssue(issue);
                      setViewMode('overview');
                    }}
                  />
                </div>

                <div className="lg:col-span-4 sticky top-20">
                  <IssueInspector
                    issue={selectedIssue}
                    onApplyFix={handleApplyFix}
                    onAskAi={handleAskAi}
                    onClose={() => setSelectedIssue(null)}
                  />
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* AI Security Copilot Chat Drawer */}
      <AiSecurityChatDrawer
        isOpen={isAiChatOpen}
        onClose={() => setIsAiChatOpen(false)}
        activeIssue={selectedIssue}
        codeContext={workspaceFiles[activeFileIndex]?.content || ''}
      />

      {/* Audit Report Export Modal */}
      <AuditReportExportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        scanResult={scanResult}
      />
    </div>
  );
}

export default App;
