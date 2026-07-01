import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '../lib/utils';
import { ShieldCheck, Activity, Target, Fingerprint } from 'lucide-react';

type LogLevel = 'info' | 'warn' | 'error' | 'success';

interface LogEntry {
  id: string;
  timestamp: string;
  agent: string;
  title: string;
  details: { label: string; payload?: any }[];
  metadata?: Record<string, string | number>;
  level: LogLevel;
}

// Maps the raw status string from the DB to a display-friendly label and colour
function mapExploitStatus(raw: string): { label: string; color: string } {
  switch ((raw || '').toUpperCase()) {
    case 'ACTIVE':      return { label: 'ACTIVE',   color: 'text-red-500' };
    case 'BLOCKED':     return { label: 'BLOCKED',  color: 'text-emerald-400' };
    case 'TESTING':     return { label: 'TESTING',  color: 'text-amber-400' };
    case 'PENDING':     return { label: 'PENDING',  color: 'text-[var(--color-border-panel)]' };
    default:            return { label: raw || '---', color: 'text-[var(--color-border-panel)]' };
  }
}

function mapPatchStatus(raw: string): { label: string; color: string } {
  switch ((raw || '').toUpperCase()) {
    case 'VERIFIED':    return { label: 'VERIFIED',     color: 'text-emerald-400' };
    case 'APPLIED':     return { label: 'APPLIED',      color: 'text-blue-400' };
    case 'SYNTAX_OK':   return { label: 'SYNTAX OK',    color: 'text-blue-300' };
    case 'FAILED_AUDIT':return { label: 'AUDIT FAIL',   color: 'text-red-500' };
    case 'SYNTAX_ERROR':return { label: 'SYNTAX ERR',   color: 'text-red-500' };
    case 'PENDING':     return { label: 'PENDING',      color: 'text-[var(--color-border-panel)]' };
    default:            return { label: raw || '---',   color: 'text-[var(--color-border-panel)]' };
  }
}

interface Props {
  liveLogs?: any[];
  exploitStatus?: string;
  patchStatus?: string;
  confidence?: number;
  signatureType?: string;
}

export function CenterLiveTerminal({
  liveLogs = [],
  exploitStatus = 'PENDING',
  patchStatus = 'PENDING',
  confidence = 0,
  signatureType = 'UNKNOWN',
}: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Map raw Python-agent logs to the rich UI LogEntry format.
  // useMemo (not useEffect+setState) so we don't trigger an extra render per WS message.
  const logs = useMemo<LogEntry[]>(() => {
    return liveLogs.map((plog, index): LogEntry => {
      let level: LogLevel = 'info';
      const s = (plog.status || '').toUpperCase();
      const a = (plog.agent || '').toUpperCase();
      if (s === 'COMPROMISED' || a === 'RED_TEAM') level = 'warn';
      if (s === 'ERROR' || s === 'SYNTAX_ERROR')    level = 'error';
      if (s === 'VERIFIED' || s === 'SECURED' || a === 'DEVELOPER' || a === 'RELEASE_MGR') level = 'success';

      const details: { label: string; payload?: any }[] = [];
      if (plog.msg && (plog.msg.includes('payload') || plog.msg.includes('scan') || plog.msg.includes('patch') || plog.msg.includes('exploit'))) {
        details.push({ label: 'Target telemetry acquired', payload: { raw: plog.msg } });
      }

      return {
        id: `log-${index}-${plog.time}`,
        timestamp: plog.time,
        agent: plog.agent,
        title: plog.msg,
        details,
        metadata: { Status: plog.status },
        level,
      };
    });
  }, [liveLogs]);

  // Auto-scroll to latest log
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const exploitDisplay  = mapExploitStatus(exploitStatus);
  const patchDisplay    = mapPatchStatus(patchStatus);
  const confidenceStr   = confidence > 0 ? `${confidence}%` : '--';
  const signatureStr    = signatureType && signatureType !== 'UNKNOWN' ? signatureType : '---';

  return (
    <div className="glass-panel flex-1 flex flex-col rounded-xl overflow-hidden relative border border-white/10">
      
      {/* Header */}
      <div className="h-12 px-4 flex items-center justify-between z-10 relative border-b shrink-0 border-white/10 bg-black/20">
        <div className="flex flex-col justify-center">
          <h2 className="text-sm font-semibold tracking-wide text-slate-200">
            Activity
          </h2>
          <span className="text-[11px] text-slate-400 mt-0.5">
            {liveLogs.length > 0 ? `${liveLogs.length} events` : 'Waiting for events'}
          </span>
        </div>
        {/* Live log count badge */}
        {liveLogs.length > 0 && (
          <div className="flex items-center gap-2 bg-[var(--color-brand)]/10 border border-[var(--color-brand)]/20 px-3 py-1.5 rounded-full">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-brand)] animate-pulse"></span>
            <span className="text-[10px] font-mono font-bold text-[var(--color-brand)] tracking-widest">
              {liveLogs.length} EVENTS
            </span>
          </div>
        )}
      </div>
      
      {/* Live metrics row — all sourced from backend state */}
      <div className="px-8 py-5 flex items-center justify-between border-b z-10 shrink-0 bg-[var(--color-border-panel)]/5 border-[var(--color-border-panel)]/5 gap-3">
        <MetricItem
          icon={<Target size={14} />}
          label="Confidence"
          value={confidenceStr}
          color={confidence >= 90 ? "text-emerald-400" : confidence > 0 ? "text-amber-400" : "text-[var(--color-border-panel)]"}
        />
        <MetricItem
          icon={<ShieldCheck size={14} />}
          label="Exploit Status"
          value={exploitDisplay.label}
          color={exploitDisplay.color}
        />
        <MetricItem
          icon={<Activity size={14} />}
          label="Patch Status"
          value={patchDisplay.label}
          color={patchDisplay.color}
        />
        <MetricItem
          icon={<Fingerprint size={14} />}
          label="Signature"
          value={signatureStr}
          color={exploitStatus === 'ACTIVE' ? "text-amber-400" : exploitStatus === 'BLOCKED' ? "text-emerald-400" : "text-[var(--color-border-panel)]"}
        />
      </div>

      {/* Log feed */}
      <div className="flex-1 relative overflow-hidden bg-[var(--color-bg-base)]/60 m-4 rounded-[24px] shadow-[inset_0_2px_10px_rgba(0,0,0,0.1)] border border-[var(--color-border-panel)]/5">
        <div
          ref={scrollRef}
          className="absolute inset-0 overflow-y-auto px-6 py-6 flex flex-col gap-5 scroll-smooth z-0"
        >
          {logs.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full gap-3 opacity-40">
              <div className="w-8 h-8 border-2 border-[var(--color-border-panel)]/40 rounded-full animate-spin border-t-transparent"></div>
              <p className="text-[12px] font-mono text-[var(--color-text-slate)] tracking-widest uppercase">Waiting for swarm activity...</p>
            </div>
          )}
          <AnimatePresence initial={false}>
            {logs.map((log, index) => (
              <motion.div 
                key={log.id}
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, ease: [0.2, 0.8, 0.2, 1] }}
                className="flex gap-6 group/log"
              >
                {/* Timestamp column */}
                <div className="w-[70px] shrink-0 pt-1">
                  <span className="text-[11px] font-mono font-bold text-[var(--color-text-slate)] opacity-100 tracking-[0.1em]">{log.timestamp}</span>
                </div>

                {/* Timeline thread */}
                <div className="relative flex flex-col items-center">
                  <div className={cn(
                    "w-2.5 h-2.5 rounded-full z-10 shrink-0 mt-1.5 transition-colors duration-500 shadow-sm",
                    log.level === 'error'   ? "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]" :
                    log.level === 'warn'    ? "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.6)]" :
                    log.level === 'success' ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]" :
                    "bg-[var(--color-border-panel)] shadow-[0_0_8px_rgba(255,255,255,0.4)]"
                  )}></div>
                  {index < logs.length - 1 && (
                    <div className="w-[1px] h-[calc(100%+24px)] absolute top-4 bg-gradient-to-b from-[var(--color-border-panel)]/20 to-[var(--color-border-panel)]/5 z-0"></div>
                  )}
                </div>

                {/* Content */}
                <div className="flex-1 pb-2 flex flex-col sm:flex-row gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-sans font-bold tracking-[0.2em] text-[var(--color-text-slate)] uppercase">{log.agent}</span>
                    </div>
                    <div className="mt-2 text-[15px] font-sans text-[var(--color-text-slate)] font-bold tracking-wide break-words">
                      {log.title}
                    </div>
                    {log.details.length > 0 && (
                      <div className="mt-3 flex flex-col gap-1.5 overflow-hidden">
                        {log.details.map((detail, idx) => (
                          <ExpandableLogChip key={idx} label={detail.label} payload={detail.payload} />
                        ))}
                      </div>
                    )}
                  </div>
                  
                  {log.metadata && (
                    <div className="w-full sm:w-[140px] shrink-0 border-t sm:border-t-0 sm:border-l border-[var(--color-border-panel)]/10 pt-3 sm:pt-1 sm:pl-4 flex flex-row sm:flex-col gap-x-4 gap-y-2 flex-wrap">
                      {Object.entries(log.metadata).map(([key, value]) => (
                        <div key={key} className="flex flex-col">
                          <span className="text-[8px] font-mono tracking-widest text-[var(--color-text-slate)] opacity-50 uppercase">{key}</span>
                          <span className="text-[10px] font-sans font-medium text-[var(--color-text-slate)] opacity-90">{value}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

// --- Sub-components ---

function SyntaxHighlightedJSON({ json }: { json: string }) {
  // Tokenize JSON into React elements — no dangerouslySetInnerHTML, no HTML string.
  // React escapes all text automatically, eliminating XSS risk entirely.
  const tokens: { text: string; color: string }[] = [];
  const regex = /("(?:\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g;
  let lastIndex = 0;
  let match;
  while ((match = regex.exec(json)) !== null) {
    // Push plain text before this match
    if (match.index > lastIndex) {
      tokens.push({ text: json.slice(lastIndex, match.index), color: 'inherit' });
    }
    const token = match[0];
    let color = 'var(--color-json-other)';
    if (/^"/.test(token)) {
      color = /:$/.test(token) ? 'var(--color-json-key)' : 'var(--color-json-str)';
    } else if (/true|false/.test(token)) {
      color = 'var(--color-json-bool)';
    } else if (/null/.test(token)) {
      color = 'var(--color-json-null)';
    }
    tokens.push({ text: token, color });
    lastIndex = regex.lastIndex;
  }
  // Push remaining plain text
  if (lastIndex < json.length) {
    tokens.push({ text: json.slice(lastIndex), color: 'inherit' });
  }

  return (
    <pre className="m-0 leading-[1.6] drop-shadow-sm font-semibold">
      {tokens.map((tok, i) => (
        <span key={i} style={{ color: tok.color }}>{tok.text}</span>
      ))}
    </pre>
  );
}

function StdoutTypewriter({ payload }: { payload: Record<string, any> }) {
  const [lines, setLines] = useState<string[]>([]);
  const allLines = React.useMemo(() => JSON.stringify(payload, null, 2).split('\n'), [payload]);

  useEffect(() => {
    let current = 0;
    const interval = setInterval(() => {
      if (current <= allLines.length) {
        setLines(allLines.slice(0, current));
        current++;
      } else {
        clearInterval(interval);
      }
    }, 40);
    return () => clearInterval(interval);
  }, [allLines]);

  return (
    <div className="relative">
      <SyntaxHighlightedJSON json={lines.join('\n')} />
      {lines.length < allLines.length && (
        <div className="w-1.5 h-3 bg-emerald-400/80 animate-pulse absolute bottom-0 left-[calc(100%+4px)]"></div>
      )}
    </div>
  );
}

function ExpandableLogChip({ label, payload }: { label: string; payload?: Record<string, any> }) {
  const [expanded, setExpanded] = useState(false);
  const hasPayload = !!payload;
  return (
    <div className="flex flex-col gap-1 w-full max-w-full">
      <div
        onClick={() => hasPayload && setExpanded(!expanded)}
        className={cn(
          "flex items-center gap-2 text-[13px] font-mono text-[var(--color-text-slate)] opacity-100 backdrop-blur-sm self-start px-3 py-1.5 rounded-lg transition-colors text-left border border-[var(--color-border-panel)]/10 shadow-sm",
          hasPayload ? "bg-[var(--color-border-panel)]/10 hover:bg-[var(--color-border-panel)]/20 cursor-pointer" : "bg-[var(--color-bg-base)]"
        )}
      >
        <span className="text-[13px] font-bold opacity-70 flex items-center justify-center w-2 text-center">
          {hasPayload ? (expanded ? 'v' : '>') : '›'}
        </span>
        <span>{label}</span>
      </div>
      <AnimatePresence>
        {expanded && hasPayload && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="text-[11px] mt-1 font-mono bg-[var(--color-bg-base)] p-3 rounded-lg border border-[var(--color-border-panel)]/10 text-[var(--color-text-slate)] w-fit overflow-x-auto max-w-full shadow-md font-medium tracking-wide flex-1">
              <StdoutTypewriter payload={payload} />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function MetricItem({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string; color: string }) {
  return (
    <div className="flex items-center gap-3 bg-[var(--color-bg-base)]/60 px-4 py-2.5 rounded-[14px] transition-transform hover:-translate-y-0.5 cursor-default group border border-[var(--color-border-panel)]/5 shadow-sm flex-1">
      <div className={cn("opacity-80 p-1.5 rounded-md bg-[var(--color-border-panel)]/5 border border-[var(--color-border-panel)]/10 text-[var(--color-border-panel)]", color)}>
        {icon}
      </div>
      <div className="min-w-0">
        <div className="text-[9px] font-sans tracking-[0.15em] text-[var(--color-text-slate)] uppercase mb-0.5 truncate">{label}</div>
        <div className={cn("text-[13px] font-sans font-bold tracking-tight truncate", color)}>{value}</div>
      </div>
    </div>
  );
}
