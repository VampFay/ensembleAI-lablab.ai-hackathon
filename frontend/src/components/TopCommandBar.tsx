import React from 'react';
import { cn } from '../lib/utils';
import { Cpu } from 'lucide-react';

// Converts raw active_agent string to a short display label and colour intent.
function parseAgent(activeAgent: string): { label: string; isRed: boolean; isIdle: boolean; isDone: boolean } {
  if (!activeAgent || activeAgent === 'IDLE') {
    return { label: 'Idle', isRed: false, isIdle: true, isDone: false };
  }
  const isRed = activeAgent.includes('RED_TEAM') || activeAgent.includes('RED TEAM');
  const label = activeAgent
    .replace(/_AGENT/gi, '')
    .replace(/_MGR/gi, ' Manager')
    .replace(/_/g, ' ')
    .trim();
  return { label, isRed, isIdle: false, isDone: false };
}

interface StatusCardProps {
  activeAgent: string;
}

function SwarmStatusCard({ activeAgent }: StatusCardProps) {
  const { label, isRed, isIdle } = parseAgent(activeAgent);

  let statusText: string;
  let subText: string;

  if (isIdle) {
    statusText = 'Idle';
    subText = 'Waiting for vulnerability report';
  } else if (isRed) {
    statusText = 'Exploit in progress';
    subText = `${label} agent running`;
  } else {
    statusText = `${label} active`;
    subText = 'Processing telemetry';
  }

  const accentColor = isRed ? 'text-red-400' : 'text-emerald-400';
  const dotColor = isRed ? 'bg-red-400' : 'bg-emerald-400';

  return (
    <div className={cn(
      "flex-1 glass-panel rounded-xl overflow-hidden relative flex items-center px-6 py-4 border",
      isRed ? "border-red-500/20" : "border-white/10"
    )}>
      <div className={cn("absolute left-0 inset-y-0 w-1", isRed ? "bg-red-500" : "bg-emerald-500")} />

      <div className="flex items-center gap-4 w-full">
        {/* Status icon — simple, no spinning rings */}
        <div className={cn(
          "w-10 h-10 rounded-lg flex items-center justify-center shrink-0",
          isRed ? "bg-red-500/10" : "bg-emerald-500/10"
        )}>
          <Cpu className={cn("w-5 h-5", accentColor)} />
        </div>

        <div className="flex flex-col flex-1 min-w-0">
          <span className="text-[10px] font-semibold tracking-wider text-slate-500 uppercase mb-0.5">Status</span>
          <div className={cn("text-lg font-bold truncate", accentColor)}>
            {statusText}
          </div>
          <div className="text-xs text-slate-400 flex items-center gap-2 truncate">
            <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", dotColor, !isIdle && "animate-pulse")} />
            {subText}
          </div>
        </div>
      </div>
    </div>
  );
}

interface TopCommandBarProps {
  activeAgent: string;
  metrics: {
    critical: number;
    success_rate: string;
    active_agents: string;
    mttr_seconds: number;
    mttr_display: string;
  };
}

export function TopCommandBar({ activeAgent, metrics }: TopCommandBarProps) {
  const mttrValue = metrics.mttr_display;
  const mttrSub = metrics.mttr_seconds > 0
    ? `${metrics.critical} resolved`
    : 'Awaiting first run';

  return (
    <div className="flex gap-4 w-full">
      <SwarmStatusCard activeAgent={activeAgent} />

      <div className="glass-panel w-[240px] shrink-0 rounded-xl p-4 flex flex-col justify-between border border-white/10">
        <span className="text-[10px] font-semibold tracking-wider text-slate-500 uppercase">
          Mean time to recovery
        </span>
        <div>
          <div className="text-2xl font-bold text-slate-100 leading-none">
            {mttrValue}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {mttrSub}
          </div>
        </div>
      </div>
    </div>
  );
}
