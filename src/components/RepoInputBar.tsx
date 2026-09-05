import React, { useState } from 'react';
import { Search, Github, Upload, Code2, Play, Sparkles, FolderOpen, AlertCircle } from 'lucide-react';
import { SAMPLE_SCENARIOS, SampleScenario } from '../data/sampleSnippets';
import { CodeFile } from '../types';

interface RepoInputBarProps {
  onScanRepo: (repoQuery: string) => void;
  onSelectSample: (scenario: SampleScenario) => void;
  onUploadFiles: (files: CodeFile[]) => void;
  onCustomCodeScan: (code: string, filename: string) => void;
  isScanning: boolean;
  activeTargetName: string;
}

export const RepoInputBar: React.FC<RepoInputBarProps> = ({
  onScanRepo,
  onSelectSample,
  onUploadFiles,
  onCustomCodeScan,
  isScanning,
  activeTargetName,
}) => {
  const [activeTab, setActiveTab] = useState<'repo' | 'samples' | 'upload' | 'paste'>('repo');
  const [repoInput, setRepoInput] = useState('');
  const [pasteCode, setPasteCode] = useState('');
  const [pasteFilename, setPasteFilename] = useState('src/app.js');
  const [errorMsg, setErrorMsg] = useState('');

  const handleRepoSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoInput.trim()) {
      setErrorMsg('Please enter a GitHub repository (e.g. expressjs/express or full URL)');
      return;
    }
    setErrorMsg('');
    onScanRepo(repoInput.trim());
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    const loadedFiles: CodeFile[] = [];
    let processed = 0;

    Array.from(fileList).forEach(file => {
      // Skip very large files
      if (file.size > 500000) {
        processed++;
        if (processed === fileList.length && loadedFiles.length > 0) {
          onUploadFiles(loadedFiles);
        }
        return;
      }

      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        loadedFiles.push({
          path: file.name,
          content: content || '',
          size: file.size,
        });
        processed++;
        if (processed === fileList.length) {
          onUploadFiles(loadedFiles);
        }
      };
      reader.readAsText(file);
    });
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const items = e.dataTransfer.files;
    if (!items || items.length === 0) return;

    const loadedFiles: CodeFile[] = [];
    let processed = 0;

    Array.from(items).forEach(file => {
      if (file.size > 500000) {
        processed++;
        if (processed === items.length && loadedFiles.length > 0) {
          onUploadFiles(loadedFiles);
        }
        return;
      }

      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        loadedFiles.push({
          path: file.name,
          content: content || '',
          size: file.size,
        });
        processed++;
        if (processed === items.length) {
          onUploadFiles(loadedFiles);
        }
      };
      reader.readAsText(file);
    });
  };

  const handlePasteSubmit = () => {
    if (!pasteCode.trim()) {
      setErrorMsg('Please paste some code to analyze');
      return;
    }
    setErrorMsg('');
    onCustomCodeScan(pasteCode, pasteFilename || 'snippet.js');
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 lg:p-6 shadow-xl mb-6">
      {/* Tab Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4 mb-5">
        <div className="flex items-center gap-1.5 p-1 bg-slate-950 rounded-xl border border-slate-800 text-xs font-medium">
          <button
            id="tab-btn-repo"
            onClick={() => setActiveTab('repo')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
              activeTab === 'repo'
                ? 'bg-blue-600 text-white shadow-sm font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Github className="w-3.5 h-3.5" />
            <span>GitHub Repository</span>
          </button>

          <button
            id="tab-btn-samples"
            onClick={() => setActiveTab('samples')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
              activeTab === 'samples'
                ? 'bg-blue-600 text-white shadow-sm font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Vulnerability Samples</span>
          </button>

          <button
            id="tab-btn-upload"
            onClick={() => setActiveTab('upload')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
              activeTab === 'upload'
                ? 'bg-blue-600 text-white shadow-sm font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload Code</span>
          </button>

          <button
            id="tab-btn-paste"
            onClick={() => setActiveTab('paste')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
              activeTab === 'paste'
                ? 'bg-blue-600 text-white shadow-sm font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Paste Snippet</span>
          </button>
        </div>

        {activeTargetName && (
          <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800">
            <span>Target:</span>
            <span className="font-mono text-blue-400 font-semibold truncate max-w-xs">{activeTargetName}</span>
          </div>
        )}
      </div>

      {/* Mode 1: GitHub Repo input */}
      {activeTab === 'repo' && (
        <div>
          <form onSubmit={handleRepoSubmit} className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <Search className="w-4 h-4" />
              </div>
              <input
                id="input-github-repo"
                type="text"
                value={repoInput}
                onChange={(e) => setRepoInput(e.target.value)}
                placeholder="Enter GitHub repo (e.g. peterkehinde673/GitHub-Security-Scanner or expressjs/express)..."
                className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                disabled={isScanning}
              />
            </div>
            <button
              id="btn-scan-repo"
              type="submit"
              disabled={isScanning}
              className="flex items-center justify-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:opacity-50 text-white font-medium text-sm rounded-xl transition-colors shadow-lg shadow-blue-600/20 cursor-pointer shrink-0"
            >
              {isScanning ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-white" />
                  <span>Scan Repository</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Repo Suggestions */}
          <div className="flex flex-wrap items-center gap-2 mt-3 text-xs text-slate-400">
            <span className="text-slate-500">Popular test repos:</span>
            {['peterkehinde673/GitHub-Security-Scanner', 'expressjs/express', 'axios/axios', 'fastify/fastify'].map(r => (
              <button
                key={r}
                type="button"
                onClick={() => {
                  setRepoInput(r);
                  onScanRepo(r);
                }}
                className="hover:text-blue-400 hover:underline cursor-pointer bg-slate-800/40 px-2 py-0.5 rounded border border-slate-800"
              >
                {r}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Mode 2: Sample Scenarios */}
      {activeTab === 'samples' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {SAMPLE_SCENARIOS.map((scenario) => (
            <div
              key={scenario.id}
              onClick={() => onSelectSample(scenario)}
              className="group p-3.5 rounded-xl bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800 hover:border-blue-500/50 transition-all cursor-pointer flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-blue-400">
                    {scenario.category}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500 uppercase">{scenario.language}</span>
                </div>
                <h3 className="text-sm font-semibold text-slate-200 group-hover:text-blue-300 transition-colors">
                  {scenario.name}
                </h3>
                <p className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                  {scenario.description}
                </p>
              </div>

              <div className="flex items-center justify-between pt-3 mt-2 border-t border-slate-800/60 text-xs text-blue-400 font-medium">
                <span className="font-mono text-[11px] text-slate-500">{scenario.filename}</span>
                <span className="flex items-center gap-1 group-hover:translate-x-0.5 transition-transform">
                  Scan Sample &rarr;
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Mode 3: File Upload */}
      {activeTab === 'upload' && (
        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDrop}
          className="border-2 border-dashed border-slate-700 hover:border-blue-500/60 rounded-xl p-6 text-center bg-slate-950/40 transition-colors"
        >
          <FolderOpen className="w-10 h-10 text-blue-400 mx-auto mb-2 opacity-80" />
          <h3 className="text-sm font-semibold text-slate-200">Drag & Drop code files or project folders</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto mt-1 mb-4">
            Supports JS, TS, Python, Go, Java, Dockerfile, YAML configs, and package manifests.
          </p>
          <label className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg cursor-pointer transition-colors border border-slate-700">
            <Upload className="w-3.5 h-3.5" />
            <span>Select Files</span>
            <input
              type="file"
              multiple
              onChange={handleFileUpload}
              className="hidden"
            />
          </label>
        </div>
      )}

      {/* Mode 4: Paste Snippet */}
      {activeTab === 'paste' && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-400 font-medium">Target Filename:</label>
            <input
              type="text"
              value={pasteFilename}
              onChange={(e) => setPasteFilename(e.target.value)}
              className="px-2.5 py-1 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
            />
          </div>
          <textarea
            id="textarea-paste-code"
            rows={7}
            value={pasteCode}
            onChange={(e) => setPasteCode(e.target.value)}
            placeholder="// Paste your source code, configuration, or Dockerfile here..."
            className="w-full p-3 bg-slate-950 border border-slate-700 rounded-xl font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
          <div className="flex justify-end">
            <button
              id="btn-scan-snippet"
              type="button"
              onClick={handlePasteSubmit}
              disabled={isScanning}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs rounded-xl shadow-lg shadow-blue-600/20 cursor-pointer disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              <span>Scan Snippet</span>
            </button>
          </div>
        </div>
      )}

      {errorMsg && (
        <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/40 border border-red-800/60 p-2.5 rounded-lg mt-3">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}
    </div>
  );
};
