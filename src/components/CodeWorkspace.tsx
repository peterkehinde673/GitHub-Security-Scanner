import React, { useState } from 'react';
import { CodeFile, SecurityIssue } from '../types';
import { FileCode, Play, Copy, Check, Download, AlertOctagon, AlertTriangle, Info, RefreshCw } from 'lucide-react';

interface CodeWorkspaceProps {
  files: CodeFile[];
  issues: SecurityIssue[];
  activeFileIndex: number;
  onSelectFileIndex: (idx: number) => void;
  onUpdateFileContent: (idx: number, newContent: string) => void;
  onTriggerRescan: () => void;
  isScanning: boolean;
  onSelectIssue: (issue: SecurityIssue) => void;
}

export const CodeWorkspace: React.FC<CodeWorkspaceProps> = ({
  files,
  issues,
  activeFileIndex,
  onSelectFileIndex,
  onUpdateFileContent,
  onTriggerRescan,
  isScanning,
  onSelectIssue,
}) => {
  const [copied, setCopied] = useState(false);
  const activeFile = files[activeFileIndex] || files[0];

  if (!activeFile) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 text-center text-slate-500">
        No files loaded in workspace.
      </div>
    );
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(activeFile.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([activeFile.content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = activeFile.path.split('/').pop() || 'code.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  // Find issues associated with active file
  const fileIssues = issues.filter(
    (i) => i.filePath === activeFile.path || activeFile.path.endsWith(i.filePath)
  );

  const lines = activeFile.content.split('\n');

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg flex flex-col h-full">
      {/* File Tabs & Actions Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 bg-slate-950 px-4 py-2.5 border-b border-slate-800">
        {/* File Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto max-w-full pb-1 sm:pb-0">
          {files.map((file, idx) => {
            const hasIssue = issues.some((i) => i.filePath === file.path || file.path.endsWith(i.filePath));
            const isActive = idx === activeFileIndex;

            return (
              <button
                key={file.path}
                onClick={() => onSelectFileIndex(idx)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors shrink-0 cursor-pointer ${
                  isActive
                    ? 'bg-slate-800 text-blue-400 font-semibold border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>{file.path.split('/').pop()}</span>
                {hasIssue && (
                  <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                )}
              </button>
            );
          })}
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 cursor-pointer"
            title="Copy Code"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
          </button>

          <button
            onClick={handleDownload}
            className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 cursor-pointer"
            title="Download File"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Export</span>
          </button>

          <button
            onClick={onTriggerRescan}
            disabled={isScanning}
            className="flex items-center gap-1 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-3 py-1 rounded-lg transition-colors cursor-pointer shadow-sm"
          >
            {isScanning ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5 fill-white" />
            )}
            <span>Re-Scan Code</span>
          </button>
        </div>
      </div>

      {/* Code Editor & Line Annotation Area */}
      <div className="flex-1 flex flex-col min-h-[420px] max-h-[600px] overflow-hidden bg-slate-950 font-mono text-xs text-slate-200">
        <div className="flex-1 overflow-y-auto flex">
          {/* Line Numbers with vulnerability indicators */}
          <div className="bg-slate-950 py-3 px-2 border-r border-slate-800/80 text-right select-none text-slate-600 font-mono text-xs w-14 shrink-0">
            {lines.map((_, idx) => {
              const lineNum = idx + 1;
              const issueOnLine = fileIssues.find((i) => i.startLine === lineNum);

              return (
                <div
                  key={lineNum}
                  className="h-5 flex items-center justify-end gap-1 px-1 relative group cursor-pointer"
                  onClick={() => issueOnLine && onSelectIssue(issueOnLine)}
                >
                  {issueOnLine && (
                    <span
                      title={`${issueOnLine.severity}: ${issueOnLine.title}`}
                      className={`w-1.5 h-1.5 rounded-full ${
                        issueOnLine.severity === 'CRITICAL'
                          ? 'bg-red-500'
                          : issueOnLine.severity === 'HIGH'
                          ? 'bg-orange-500'
                          : 'bg-yellow-500'
                      }`}
                    />
                  )}
                  <span>{lineNum}</span>
                </div>
              );
            })}
          </div>

          {/* Editable Code Area */}
          <div className="flex-1 relative">
            <textarea
              value={activeFile.content}
              onChange={(e) => onUpdateFileContent(activeFileIndex, e.target.value)}
              className="w-full h-full p-3 bg-transparent text-slate-200 font-mono text-xs leading-5 resize-none focus:outline-none whitespace-pre overflow-x-auto"
              spellCheck={false}
            />
          </div>
        </div>
      </div>

      {/* Workspace Footer info */}
      <div className="bg-slate-950 px-4 py-2 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
        <span className="truncate">{activeFile.path}</span>
        <div className="flex items-center gap-3">
          <span>{lines.length} lines</span>
          <span>{fileIssues.length} issue(s) detected in this file</span>
        </div>
      </div>
    </div>
  );
};
