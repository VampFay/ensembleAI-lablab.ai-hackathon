import React, { useMemo, useState } from 'react';
import { CheckCircle2, Loader2, Columns, Rows, Shield, FileCode } from 'lucide-react';
import { cn } from '../lib/utils';

function syntaxHighlight(code: string) {
  if (!code) return <span> </span>;

  // Tokenize without building HTML strings — returns React elements directly.
  // No dangerouslySetInnerHTML needed; React escapes all text automatically.
  const keywords = new Set([
    'async','function','const','let','var','if','else','return','try','catch',
    'process','env','next','def','import','from','class','self','await','for',
    'in','elif','yield','null','None','true','false','True','False','echo',
    'require','include','new','static','public','private','void','string','int'
  ]);

  // Split into tokens: strings, comments, words, and everything else
  const tokens: { text: string; type: 'string' | 'comment' | 'keyword' | 'plain' }[] = [];
  const regex = /('(?:[^'\\]|\\.)*?'|"(?:[^"\\]|\\.)*?")|(\/\/[^\n]*|#[^\n]*)|(\b\w+\b)|([^\w]+)/g;
  let match;
  while ((match = regex.exec(code)) !== null) {
    if (match[1]) {
      tokens.push({ text: match[1], type: 'string' });
    } else if (match[2]) {
      tokens.push({ text: match[2], type: 'comment' });
    } else if (match[3]) {
      tokens.push({ text: match[3], type: keywords.has(match[3]) ? 'keyword' : 'plain' });
    } else if (match[4]) {
      tokens.push({ text: match[4], type: 'plain' });
    }
  }

  return (
    <span>
      {tokens.map((tok, i) => {
        if (tok.type === 'string') return <span key={i} style={{ color: 'var(--color-syntax-string)' }}>{tok.text}</span>;
        if (tok.type === 'comment') return <span key={i} style={{ color: 'var(--color-syntax-comment)' }} className="italic opacity-80">{tok.text}</span>;
        if (tok.type === 'keyword') return <span key={i} style={{ color: 'var(--color-syntax-keyword)' }} className="font-bold">{tok.text}</span>;
        return <span key={i}>{tok.text}</span>;
      })}
    </span>
  );
}

interface DiffLine {
  type: 'unchanged' | 'removed' | 'added';
  b: string | null;
  a: string | null;
}

function computeDiff(before: string, after: string): DiffLine[] {
  const beforeLines = before.split('\n');
  const afterLines  = after.split('\n');
  const maxLen = Math.max(beforeLines.length, afterLines.length);
  const lines: DiffLine[] = [];
  
  for (let i = 0; i < maxLen; i++) {
    const b = beforeLines[i] ?? undefined;
    const a = afterLines[i]  ?? undefined;
    
    if (b === a) {
      lines.push({ type: 'unchanged', b: b ?? '', a: a ?? '' });
    } else if (b !== undefined && a === undefined) {
      lines.push({ type: 'removed', b, a: null });
    } else if (b === undefined && a !== undefined) {
      lines.push({ type: 'added', b: null, a });
    } else {
      lines.push({ type: 'removed', b: b!, a: null });
      lines.push({ type: 'added',   b: null, a: a! });
    }
  }
  return lines;
}

// Infer a human-readable language/stack label from the file path
function inferStackLabel(targetFile: string): string {
  if (!targetFile) return 'Awaiting Target';
  if (targetFile.includes('.php'))  return 'PHP (WordPress Plugin)';
  if (targetFile.includes('.py'))   return 'Python (FastAPI)';
  if (targetFile.includes('.js'))   return 'Node.js (Express)';
  if (targetFile.includes('.ts'))   return 'TypeScript';
  if (targetFile.includes('.go'))   return 'Go';
  return targetFile.split('/').pop() || targetFile;
}

interface Props {
  codeBefore?: string;
  codeAfter?: string;
  targetFile?: string;
  rootCause?: string;
  fixApplied?: string;
  securityImpact?: string;
  wafRuleFile?: string;
  deployStatus?: string;
  onApprove?: () => void;
  onReject?: () => void;
}

const AWAITING_CODE = '// Awaiting target assignment from Triage...';

export function RightPanelDiffViewer({
  codeBefore = AWAITING_CODE,
  codeAfter  = '// Awaiting patch from Developer agent...',
  targetFile = '',
  rootCause  = '',
  fixApplied = '',
  securityImpact = '',
  wafRuleFile = '',
  deployStatus = 'PENDING',
  onApprove,
  onReject,
}: Props) {
  const [viewMode, setViewMode] = useState<'split' | 'inline'>('split');

  const isAwaiting = codeBefore.includes('Awaiting') || !targetFile;
  
  const diffLines = useMemo<DiffLine[]>(() => {
    if (isAwaiting) return [];
    return computeDiff(codeBefore, codeAfter);
  }, [codeBefore, codeAfter, isAwaiting]);

  const stackLabel = inferStackLabel(targetFile);
  const filePath   = targetFile || '---';

  // Derive deploy badge from real state
  const deployed  = deployStatus === 'DEPLOYED';
  const readyToDeploy = deployStatus === 'READY';
  const awaitingApproval = deployStatus === 'AWAITING_APPROVAL';
  const rejected = deployStatus === 'REJECTED';

  const deployLabel = deployed 
    ? 'WAF rule generated' 
    : readyToDeploy 
    ? 'Patch ready' 
    : awaitingApproval
    ? 'Awaiting Approval'
    : rejected
    ? 'Patch Rejected'
    : 'Pending verification';
    
  const deployIcon  = deployed 
    ? <CheckCircle2 className="w-4 h-4" /> 
    : readyToDeploy 
    ? <CheckCircle2 className="w-4 h-4 text-amber-400" /> 
    : awaitingApproval
    ? <Loader2 className="w-4 h-4 animate-spin text-amber-500" />
    : rejected
    ? <CheckCircle2 className="w-4 h-4 text-red-500" />
    : <Loader2 className="w-4 h-4 animate-spin opacity-50" />;
    
  const deployColor = deployed 
    ? 'text-emerald-400' 
    : readyToDeploy 
    ? 'text-amber-400' 
    : awaitingApproval
    ? 'text-amber-500'
    : rejected
    ? 'text-red-500'
    : 'text-slate-400';

  return (
    <div className="glass-panel w-full h-full flex flex-col rounded-xl overflow-hidden transition-colors duration-300 border border-white/10">
      
      {/* Header */}
      <div className="h-16 border-b border-[var(--color-border-panel)]/10 bg-[var(--color-border-panel)]/5 backdrop-blur-md flex items-center px-6 justify-between shrink-0 z-10 relative">
        <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-[var(--color-brand)]/40 to-transparent"></div>
        <div className="flex items-center gap-4">
          <span className="text-xs font-medium tracking-wide text-emerald-400">Code revisions</span>
          <div className="flex items-center gap-1 bg-[var(--color-bg-base)]/50 rounded-full p-1 border border-[var(--color-border-panel)]/10 shadow-sm">
            <button
              onClick={() => setViewMode('split')}
              className={cn("w-10 h-10 flex items-center justify-center rounded-full transition-all cursor-pointer",
                viewMode === 'split' ? "bg-[var(--color-border-panel)]/10 shadow-inner border border-[var(--color-border-panel)]/20 text-[var(--color-text-slate)]" : "text-[var(--color-text-slate)] opacity-80 hover:opacity-100 hover:bg-[var(--color-border-panel)]/10"
              )}
              title="Side-by-Side View"
            ><Columns size={16} /></button>
            <button
              onClick={() => setViewMode('inline')}
              className={cn("w-10 h-10 flex items-center justify-center rounded-full transition-all cursor-pointer",
                viewMode === 'inline' ? "bg-[var(--color-border-panel)]/10 shadow-inner border border-[var(--color-border-panel)]/20 text-[var(--color-text-slate)]" : "text-[var(--color-text-slate)] opacity-80 hover:opacity-100 hover:bg-[var(--color-border-panel)]/10"
              )}
              title="Inline View"
            ><Rows size={16} /></button>
          </div>
        </div>
        {/* Live stack label from target_file */}
        <div className="px-5 h-10 flex items-center gap-2 rounded-full border border-[var(--color-border-panel)]/20 text-[11px] text-[var(--color-brand)] font-bold tracking-widest cursor-default bg-[var(--color-bg-base)]/40 shadow-sm">
          <FileCode size={14} className="opacity-70" />
          <span className="truncate max-w-[160px]">{stackLabel}</span>
        </div>
      </div>
      
      {/* File path row — live from backend */}
      <div className="px-5 py-3 border-b border-[var(--color-border-panel)]/20 bg-[var(--color-bg-base)] text-[11px] text-[var(--color-text-slate)] opacity-80 font-mono flex items-center z-0 gap-2">
        <span className="text-[var(--color-brand)] opacity-70">[FILE]</span>
        <span className="truncate">{filePath}</span>
      </div>
      
      {/* Before/After column headers (split view only) */}
      {viewMode === 'split' && !isAwaiting && (
        <div className="grid grid-cols-2 text-[11px] border-b border-[var(--color-border-panel)]/20 shrink-0 font-sans tracking-[0.15em] font-bold text-center">
          <div className="py-3 border-r border-red-500/20 flex items-center justify-center gap-2 text-red-500 bg-[var(--color-bg-base)] shadow-[inset_0_-2px_0_rgba(239,68,68,0.5)]">
            <span>Before</span>
          </div>
          <div className="py-3 flex items-center justify-center gap-2 text-emerald-400 bg-[var(--color-bg-base)] shadow-[inset_0_-2px_0_rgba(52,211,153,0.5)]">
            <span>After</span>
          </div>
        </div>
      )}

      {/* Diff viewport */}
      <div className="flex-1 overflow-auto bg-[var(--color-bg-base)] shadow-[inset_0_4px_20px_rgba(0,0,0,0.1)] text-[13px] font-mono relative leading-[1.6]">
        <div className="absolute inset-0 bg-gradient-to-b from-[var(--color-border-panel)]/5 to-transparent pointer-events-none z-10"></div>
        
        {isAwaiting ? (
          /* Empty state: waiting for Triage to assign a target */
          <div className="flex flex-col items-center justify-center h-full gap-4 opacity-30 z-0 relative">
            <Loader2 className="w-8 h-8 animate-spin text-[var(--color-brand)]" />
            <p className="text-[12px] font-mono text-[var(--color-text-slate)] tracking-widest uppercase">Awaiting target from Triage...</p>
          </div>
        ) : (
          <div className={cn("relative z-0 p-4 pt-5", viewMode === 'split' ? "min-w-[800px]" : "min-w-full")}>
            {(() => {
              let bIdx = 1;
              let aIdx = 1;

              if (viewMode === 'inline') {
                const inlineLines = diffLines.map((line) => {
                  if (line.type === 'unchanged') return { ...line, bIdx: bIdx++, aIdx: aIdx++ };
                  if (line.type === 'removed')   return { ...line, bIdx: bIdx++, aIdx: null };
                  return { ...line, bIdx: null, aIdx: aIdx++ };
                });
                return inlineLines.map((line, idx) => (
                  <div key={idx} className="flex relative group leading-[1.6]">
                    <div className={cn("flex w-full relative transition-colors",
                      line.type === 'removed' ? 'bg-red-500/[0.06] shadow-[inset_2px_0_0_rgba(239,68,68,0.8)]' :
                      line.type === 'added'   ? 'bg-emerald-500/[0.06] shadow-[inset_2px_0_0_rgba(16,185,129,0.8)]' :
                      'hover:bg-[var(--color-border-panel)]/5'
                    )}>
                      <div className="w-8 shrink-0 text-right pr-2 select-none opacity-40 text-[9px] border-r border-[var(--color-border-panel)]/5 mr-3 text-[var(--color-text-slate)]">{(line as any).bIdx || ''}</div>
                      <div className="w-8 shrink-0 text-right pr-2 select-none opacity-40 text-[9px] border-r border-[var(--color-border-panel)]/5 mr-3 text-[var(--color-text-slate)]">{(line as any).aIdx || ''}</div>
                      <div className={cn("w-4 shrink-0 text-center select-none opacity-50",
                        line.type === 'removed' ? "text-[var(--color-diff-red)]" :
                        line.type === 'added'   ? "text-[var(--color-diff-green)]" : ""
                      )}>{line.type === 'removed' ? '-' : line.type === 'added' ? '+' : ''}</div>
                      <div className={cn("flex-1 whitespace-pre", "text-[var(--color-text-slate)] font-medium")}>
                        {line.type === 'removed' ? syntaxHighlight(line.b || '') : syntaxHighlight(line.a || '')}
                      </div>
                    </div>
                  </div>
                ));
              }

              // Split view
              return diffLines.map((line, idx) => {
                const lineBIdx = (line.type === 'unchanged' || line.type === 'removed') ? bIdx++ : null;
                const lineAIdx = (line.type === 'unchanged' || line.type === 'added')   ? aIdx++ : null;
                return (
                  <div key={idx} className="grid grid-cols-2 relative group leading-[1.6]">
                    <div className={cn("py-0.5 border-r border-[var(--color-border-panel)]/5 flex w-full relative transition-colors",
                      line.type === 'removed' ? 'bg-red-500/[0.06] shadow-[inset_2px_0_0_rgba(239,68,68,0.8)]' : 'hover:bg-[var(--color-border-panel)]/5',
                      line.b === null ? 'opacity-10 pointer-events-none' : ''
                    )}>
                      <div className="w-8 shrink-0 text-right pr-2 select-none opacity-40 text-[9px] border-r border-[var(--color-border-panel)]/5 mr-3 text-[var(--color-text-slate)] flex items-center justify-end">{lineBIdx || ''}</div>
                      <div className="w-4 shrink-0 text-center select-none opacity-50 text-[var(--color-diff-red)] flex items-center justify-center">{line.type === 'removed' ? '-' : ''}</div>
                      <div className={cn("flex-1 whitespace-pre", line.type === 'removed' ? 'text-[var(--color-text-slate)] font-medium' : 'text-[var(--color-text-slate)]')}>{syntaxHighlight(line.b || '')}</div>
                    </div>
                    <div className={cn("py-0.5 flex w-full relative transition-colors",
                      line.type === 'added' ? 'bg-emerald-500/[0.06] shadow-[inset_2px_0_0_rgba(16,185,129,0.8)]' : 'hover:bg-[var(--color-border-panel)]/5',
                      line.a === null ? 'opacity-10 pointer-events-none' : ''
                    )}>
                      <div className="w-8 shrink-0 text-right pr-2 select-none opacity-40 text-[9px] border-r border-[var(--color-border-panel)]/5 mr-3 text-[var(--color-text-slate)] flex items-center justify-end">{lineAIdx || ''}</div>
                      <div className="w-4 shrink-0 text-center select-none opacity-50 text-[var(--color-diff-green)] flex items-center justify-center">{line.type === 'added' ? '+' : ''}</div>
                      <div className={cn("flex-1 whitespace-pre", line.type === 'added' ? 'text-[var(--color-text-slate)] font-medium' : 'text-[var(--color-text-slate)]')}>{syntaxHighlight(line.a || '')}</div>
                    </div>
                  </div>
                );
              });
            })()}
          </div>
        )}
      </div>
      
      {/* AI Remediation Summary — all fields from backend state */}
      <div className="px-6 py-4 bg-[var(--color-bg-base)] border-t border-[var(--color-border-panel)]/10 z-10 shrink-0">
        <h3 className="text-[10px] font-display font-bold tracking-[0.2em] text-[var(--color-text-slate)] opacity-80 uppercase mb-3 flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-emerald-500" />
          Remediation summary
        </h3>
        <div className="grid grid-cols-3 gap-3">
          <SummaryItem label="Root Cause"     value={rootCause   || '---'} />
          <SummaryItem label="Fix Applied"    value={fixApplied  || '---'} />
          <SummaryItem label="Security Impact" value={securityImpact || '---'} highlight />
        </div>
      </div>
      
      {/* Deploy / WAF status row */}
      <div className="p-4 pt-0 bg-transparent shrink-0 flex flex-col justify-center z-10 rounded-xl relative overflow-hidden mt-2 gap-3">
        <div className="w-full mx-2 flex gap-3">
          <div className={cn("flex-1 px-6 py-3 rounded-[20px] bg-[var(--color-bg-base)] border flex justify-between items-center relative overflow-hidden backdrop-blur-md shadow-sm",
            deployed ? "border-[var(--color-brand)]/20 shadow-[0_0_20px_rgba(16,185,129,0.1)]" : (readyToDeploy || awaitingApproval) ? "border-amber-400/20" : rejected ? "border-red-500/20" : "border-[var(--color-border-panel)]/10"
          )}>
            <div className="flex flex-col items-start gap-1 z-10">
              <span className={cn("text-[13px] tracking-[0.1em] font-sans font-bold flex items-center gap-2", deployColor)}>
                {deployIcon}
                {deployLabel}
              </span>
              <span className="text-[9px] font-mono tracking-widest uppercase pt-0.5 text-[var(--color-text-slate)] opacity-80">
                {wafRuleFile ? `WAF: ${wafRuleFile}` : 'No WAF rule generated yet'}
              </span>
            </div>
            <div className="flex flex-col items-end z-10">
              <span className="text-[9px] font-mono tracking-widest uppercase block text-[var(--color-text-slate)] opacity-60">STATUS</span>
              <span className={cn("text-[10px] font-sans tracking-widest font-bold uppercase mt-0.5 block drop-shadow-sm", deployColor)}>
                {deployStatus || 'PENDING'}
              </span>
            </div>
          </div>
        </div>

        {/* Human in the loop approval controls */}
        {awaitingApproval && (
          <div className="w-full px-2 flex gap-3 animate-fade-in">
            <button
              onClick={onReject}
              className="flex-1 py-2.5 rounded-lg border border-red-500/30 bg-red-500/10 hover:bg-red-500/20 text-red-400 font-semibold text-xs transition-colors cursor-pointer text-center uppercase tracking-wider"
            >
              Reject Patch
            </button>
            <button
              onClick={onApprove}
              className="flex-1 py-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 font-semibold text-xs transition-colors cursor-pointer text-center uppercase tracking-wider"
            >
              Approve WAF Rule
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function SummaryItem({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className={cn("flex flex-col gap-1.5", highlight ? "bg-[var(--color-brand)]/5 p-2 rounded-lg border border-[var(--color-brand)]/10" : "")}>
      <span className={cn("text-[9px] font-mono tracking-widest uppercase", highlight ? "text-[var(--color-brand)] opacity-90" : "text-[var(--color-text-slate)] opacity-60")}>
        {label}
      </span>
      <span className={cn("text-[11px] font-sans font-medium leading-tight", highlight ? "text-[var(--color-brand)] drop-shadow-sm" : "text-[var(--color-text-slate)]")}>
        {value}
      </span>
    </div>
  );
}
