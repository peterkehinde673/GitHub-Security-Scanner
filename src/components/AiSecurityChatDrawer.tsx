import React, { useState, useRef, useEffect } from 'react';
import { Sparkles, Send, Bot, User, X, Shield, RefreshCw } from 'lucide-react';
import Markdown from 'react-markdown';
import { ChatMessage, SecurityIssue } from '../types';

interface AiSecurityChatDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  activeIssue: SecurityIssue | null;
  codeContext: string;
}

export const AiSecurityChatDrawer: React.FC<AiSecurityChatDrawerProps> = ({
  isOpen,
  onClose,
  activeIssue,
  codeContext,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome-1',
      role: 'assistant',
      content:
        '👋 Hello! I am your **AI Security Copilot**. I can help you write secure unit tests, explain complex exploit vectors (OWASP Top 10, CWEs), harden IaC manifests, or generate defense-in-depth code patches.',
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isSending, setIsSending] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // When active issue changes, suggest a prompt
  useEffect(() => {
    if (activeIssue) {
      setMessages((prev) => [
        ...prev,
        {
          id: `issue-prompt-${Date.now()}`,
          role: 'system',
          content: `Focused on finding: **${activeIssue.title}** (${activeIssue.severity} - ${activeIssue.cwe || activeIssue.category}) in \`${activeIssue.filePath}\``,
          timestamp: new Date().toLocaleTimeString(),
          relatedIssueId: activeIssue.id,
        },
      ]);
    }
  }, [activeIssue]);

  if (!isOpen) return null;

  const handleSendMessage = async (customText?: string) => {
    const text = customText || inputMessage;
    if (!text.trim() || isSending) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: text.trim(),
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputMessage('');
    setIsSending(true);

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: [...messages, userMsg],
          codeContext,
          activeIssue,
        }),
      });

      const data = await res.json();

      const assistantMsg: ChatMessage = {
        id: `assistant-${Date.now()}`,
        role: 'assistant',
        content: data.reply || 'No response received from security copilot.',
        timestamp: new Date().toLocaleTimeString(),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content: `Error contacting AI security server: ${err.message}`,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsSending(false);
    }
  };

  const quickPrompts = [
    'Write unit tests to verify the patch',
    'Explain the attack vector and exploit payload',
    'How do I configure CI/CD to prevent this vulnerability?',
  ];

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col">
      {/* Drawer Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-purple-600/30 border border-purple-500/50 flex items-center justify-center text-purple-300">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>AI Security Copilot</span>
              <span className="px-1.5 py-0.2 text-[10px] font-semibold bg-purple-950 text-purple-300 rounded border border-purple-800">
                Gemini 3.7
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">DevSecOps Code Hardening & Exploit Analysis</p>
          </div>
        </div>

        <button
          onClick={onClose}
          className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Messages List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex gap-3 ${
              msg.role === 'user' ? 'justify-end' : 'justify-start'
            }`}
          >
            {msg.role === 'assistant' && (
              <div className="w-7 h-7 rounded-lg bg-purple-600/20 border border-purple-500/40 flex items-center justify-center text-purple-300 shrink-0 mt-0.5">
                <Bot className="w-4 h-4" />
              </div>
            )}

            <div
              className={`max-w-[85%] rounded-2xl p-3.5 text-xs ${
                msg.role === 'user'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : msg.role === 'system'
                  ? 'bg-slate-950/80 text-slate-300 border border-purple-900/50 text-[11px]'
                  : 'bg-slate-950 text-slate-200 border border-slate-800'
              }`}
            >
              {msg.role === 'user' ? (
                <p className="whitespace-pre-wrap">{msg.content}</p>
              ) : (
                <div className="prose prose-invert prose-xs max-w-none space-y-2 leading-relaxed">
                  <Markdown>{msg.content}</Markdown>
                </div>
              )}
              <div
                className={`text-[9px] mt-1.5 opacity-60 text-right ${
                  msg.role === 'user' ? 'text-blue-100' : 'text-slate-500'
                }`}
              >
                {msg.timestamp}
              </div>
            </div>

            {msg.role === 'user' && (
              <div className="w-7 h-7 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-300 shrink-0 mt-0.5">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {isSending && (
          <div className="flex items-center gap-2 text-xs text-purple-400 bg-slate-950/80 p-3 rounded-xl border border-purple-900/40 w-fit">
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span>Analyzing code & formulating security guidance...</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Quick Prompts */}
      <div className="px-4 py-2 bg-slate-950/90 border-t border-slate-800/80">
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
          {quickPrompts.map((prompt, i) => (
            <button
              key={i}
              type="button"
              onClick={() => handleSendMessage(prompt)}
              className="text-[11px] whitespace-nowrap px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 transition-colors shrink-0 cursor-pointer"
            >
              {prompt}
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage();
        }}
        className="p-3 bg-slate-950 border-t border-slate-800 flex items-center gap-2"
      >
        <input
          type="text"
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          placeholder="Ask a security question or request hardening code..."
          className="flex-1 px-3.5 py-2 bg-slate-900 border border-slate-700/80 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
          disabled={isSending}
        />
        <button
          type="submit"
          disabled={!inputMessage.trim() || isSending}
          className="p-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white rounded-xl transition-colors cursor-pointer shrink-0"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
};
