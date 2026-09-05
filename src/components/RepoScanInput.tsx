import React, { useState } from 'react';
import { Search, Github, Upload, Code2, AlertCircle, Sparkles, CheckCircle2 } from 'lucide-react';
import { SAMPLE_SCENARIOS, SampleScenario } from '../data/sampleSnippets';
import { CodeFile } from '../types';

interface RepoScanInputProps {
  onScanRepo: (url: string) => void;
  onSelectSample: (scenario: SampleScenario) => void;
  onUploadFiles: (files: CodeFile[]) => void;
  onCustomCodeScan: (code: string, filename: string) => void;
  isScanning: boolean;
  activeTargetName: string;
}

export const RepoScanInput: React.FC<RepoScanInputProps> = ({
  onScanRepo,
  onSelectSample,
  onUploadFiles,
  onCustomCodeScan,
  isScanning,
  activeTargetName,
}) => {
  const [repoUrl, setRepoUrl] = useState('');
  const [inputMode, setInputMode] = useState<'url' | 'sample' | 'custom' | 'upload'>('url');
  const [customCode, setCustomCode] = useState('');
  const [customFilename, setCustomFilename] = useState('app.ts');
  const [inputError, setInputError] = useState('');

  const handleRepoSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setInputError('');

    if (!repoUrl.trim()) {
      setInputError('Please enter a valid public GitHub repository URL or shorthand (e.g. owner/repo).');
      return;
    }

    onScanRepo(repoUrl.trim());
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    const filesArray: CodeFile[] = [];
    let readCount = 0;

    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      if (file.size > 500 * 1024) continue; // Skip huge files

      const reader = new FileReader();
      reader.onload = (event) => {
        const text = (event.target?.result as string) || '';
        filesArray.push({
          path: file.name,
          content: text,
          sizeBytes: file.size,
        });
        readCount++;
        if (readCount === fileList.length) {
          if (filesArray.length > 0) {
            onUploadFiles(filesArray);
          }
        }
      };
      reader.readAsText(file);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 mb-6 shadow-xl">
      {/* Title & Mode Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
            Target Repository & Source Code
          </h2>
          <p className="text-xs text-slate-400">
            Enter a public GitHub repository or test with pre-built vulnerability suites.
          </p>
        </div>

        {/* Input Mode Pills */}
        <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
          <button
            id="mode-btn-url"
            type="button"
            onClick={() => setInputMode('url')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              inputMode === 'url' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Github className="w-3.5 h-3.5" />
            <span>GitHub URL</span>
          </button>

          <button
            id="mode-btn-sample"
            type="button"
            onClick={() => setInputMode('sample')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              inputMode === 'sample' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-yellow-400" />
            <span>Sample Scenarios</span>
          </button>

          <button
            id="mode-btn-custom"
            type="button"
            onClick={() => setInputMode('custom')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              inputMode === 'custom' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Paste Code</span>
          </button>

          <button
            id="mode-btn-upload"
            type="button"
            onClick={() => setInputMode('upload')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              inputMode === 'upload' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload Files</span>
          </button>
        </div>
      </div>

      {/* Mode 1: GitHub URL Form */}
      {inputMode === 'url' && (
        <form onSubmit={handleRepoSubmit} className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <Github className="w-4 h-4" />
              </div>
              <input
                id="input-github-url"
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repo or owner/repo (e.g. expressjs/express)"
                className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono"
                disabled={isScanning}
              />
            </div>

            <button
              id="btn-scan-repo"
              type="submit"
              disabled={isScanning}
              className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs sm:text-sm font-semibold rounded-xl transition-all shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2 cursor-pointer shrink-0"
            >
              <Search className="w-4 h-4" />
              <span>{isScanning ? 'Auditing Code...' : 'Scan Repository'}</span>
            </button>
          </div>

          {inputError && (
            <div className="flex items-center gap-1.5 text-xs text-red-400 bg-red-950/40 p-2.5 rounded-lg border border-red-900/50">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{inputError}</span>
            </div>
          )}

          <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
            <span>Current target: <strong className="text-slate-300">{activeTargetName}</strong></span>
            <span>Timeout: 15s • Read-only • Safe Sandbox Execution</span>
          </div>
        </form>
      )}

      {/* Mode 2: Sample Scenarios */}
      {inputMode === 'sample' && (
        <div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {SAMPLE_SCENARIOS.map((scenario) => {
              const isSelected = activeTargetName === scenario.name;
              return (
                <button
                  key={scenario.id}
                  id={`sample-card-${scenario.id}`}
                  onClick={() => onSelectSample(scenario)}
                  disabled={isScanning}
                  className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                    isSelected
                      ? 'bg-blue-950/40 border-blue-500 text-blue-200 shadow-md'
                      : 'bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <span className="font-semibold text-xs text-slate-100">{scenario.name}</span>
                      {isSelected && <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />}
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
                      {scenario.description}
                    </p>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 mt-2">
                    {scenario.filename}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Mode 3: Paste Custom Snippet */}
      {inputMode === 'custom' && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={customFilename}
              onChange={(e) => setCustomFilename(e.target.value)}
              placeholder="filename.ext (e.g. server.ts, app.py)"
              className="px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200"
            />
          </div>
          <textarea
            value={customCode}
            onChange={(e) => setCustomCode(e.target.value)}
            placeholder="// Paste raw source code, Dockerfile, or manifest to scan immediately..."
            rows={5}
            className="w-full p-3 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={() => {
              if (customCode.trim()) {
                onCustomCodeScan(customCode, customFilename);
              }
            }}
            disabled={!customCode.trim() || isScanning}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold rounded-xl cursor-pointer"
          >
            Scan Snippet
          </button>
        </div>
      )}

      {/* Mode 4: File Upload */}
      {inputMode === 'upload' && (
        <div className="border-2 border-dashed border-slate-800 rounded-xl p-6 text-center bg-slate-950/50">
          <Upload className="w-8 h-8 text-slate-500 mx-auto mb-2" />
          <p className="text-xs text-slate-300 font-medium mb-1">
            Drag and drop project code files here, or browse from computer
          </p>
          <p className="text-[11px] text-slate-500 mb-3">
            Supports .js, .ts, .py, .go, .php, .java, Dockerfile, package.json, requirements.txt
          </p>
          <label className="inline-block px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl cursor-pointer border border-slate-700">
            <span>Browse Files</span>
            <input
              type="file"
              multiple
              onChange={handleFileUpload}
              className="hidden"
            />
          </label>
        </div>
      )}
    </div>
  );
};
