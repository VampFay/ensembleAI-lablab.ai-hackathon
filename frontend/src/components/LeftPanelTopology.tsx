import React from 'react';
import { cn } from '../lib/utils';
import { Search, AlertTriangle, TerminalSquare, Shield, Users } from 'lucide-react';

type AgentState = 'idle' | 'active' | 'done' | 'error';

interface AgentNode {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  // Which activeAgent string from the backend maps to this node
  matchStrings: string[];
}

const AGENTS: AgentNode[] = [
  { id: 'triage',   label: 'Triage Agent',     icon: Search,         matchStrings: ['TRIAGE'] },
  { id: 'redteam',  label: 'Red Team',          icon: AlertTriangle,  matchStrings: ['RED_TEAM', 'RED TEAM'] },
  { id: 'dev',      label: 'Patch Developer',   icon: TerminalSquare, matchStrings: ['DEVELOPER', 'DEV'] },
  { id: 'audit',    label: 'Rigor Auditor',     icon: Shield,         matchStrings: ['AUDITOR', 'AUDIT'] },
  { id: 'release',  label: 'Release Manager',   icon: Users,          matchStrings: ['RELEASE_MGR', 'RELEASE'] },
];

function deriveState(nodeId: string, activeAgent: string, step: number): AgentState {
  const isActive = activeAgent && AGENTS.find(a => a.id === nodeId)?.matchStrings.some(s => activeAgent.toUpperCase().includes(s));
  if (isActive) return 'active';

  // Derive "done" from timeline_step — agents that have already run
  const stepOrder: Record<string, number> = { triage: 1, redteam: 2, dev: 3, audit: 4, release: 6 };
  const agentStep = stepOrder[nodeId];
  if (step > agentStep) return 'done';
  return 'idle';
}

function stateStyles(state: AgentState) {
  switch (state) {
    case 'active':
      return {
        dot: 'bg-emerald-400 animate-pulse',
        text: 'text-emerald-400',
        label: 'Active',
      };
    case 'done':
      return {
        dot: 'bg-emerald-600',
        text: 'text-slate-400',
        label: 'Done',
      };
    case 'error':
      return {
        dot: 'bg-red-500',
        text: 'text-red-400',
        label: 'Error',
      };
    default:
      return {
        dot: 'bg-slate-600',
        text: 'text-slate-500',
        label: 'Idle',
      };
  }
}

interface Props {
  simulationStep?: number;
  activeAgent?: string;
}

export function LeftPanelTopology({ simulationStep = 0, activeAgent = 'IDLE' }: Props) {
  return (
    <div className="glass-panel w-full h-full flex flex-col rounded-xl overflow-hidden border border-white/10">
      <div className="h-12 px-4 flex items-center justify-between shrink-0 border-b border-white/10 bg-black/20">
        <span className="text-xs font-semibold tracking-wide text-slate-300 uppercase">Agent Status</span>
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
          <span className="text-[10px] text-slate-400 uppercase tracking-wider">Live</span>
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-1">
        {AGENTS.map((agent) => {
          const state = deriveState(agent.id, activeAgent, simulationStep);
          const styles = stateStyles(state);
          const Icon = agent.icon;

          return (
            <div
              key={agent.id}
              className={cn(
                "flex items-center gap-3 p-2.5 rounded-lg transition-colors",
                state === 'active' ? 'bg-emerald-500/10 border border-emerald-500/20' : 'hover:bg-white/5'
              )}
            >
              {/* Status dot */}
              <span className={cn("w-2 h-2 rounded-full shrink-0", styles.dot)} />

              {/* Icon */}
              <div className={cn(
                "w-8 h-8 rounded-md flex items-center justify-center shrink-0",
                state === 'active' ? 'bg-emerald-500/20' : 'bg-white/5'
              )}>
                <Icon className={cn("w-4 h-4", styles.text)} />
              </div>

              {/* Label + status */}
              <div className="flex-1 min-w-0">
                <div className={cn("text-sm font-medium", state === 'active' ? 'text-emerald-400' : 'text-slate-200')}>
                  {agent.label}
                </div>
                <div className={cn("text-[11px]", styles.text)}>
                  {styles.label}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
