import React from 'react';
import { cn } from '../lib/utils';

// Pipeline mirrors the 5-agent workflow in ensemble_ai/agents.py:
// Step 0=IDLE, 1=TRIAGE, 2=RED_TEAM, 3=DEVELOPER, 4=AUDITOR, 5=RE-VERIFY, 6=RELEASE_MGR
type NodeStatus = 'completed' | 'active' | 'pending' | 'error';

interface PipelineNode {
  id: string;
  label: string;
  cx: string;
  cy: string;
  labelPos: 'top' | 'bottom';
  activeAtStep: number;
  completedAfterStep: number;
}

const PIPELINE: PipelineNode[] = [
  { id: 'ingest',  label: 'Ingest',       cx: '10%', cy: '50%', labelPos: 'bottom', activeAtStep: 1, completedAfterStep: 1 },
  { id: 'verify',  label: 'Red Team',     cx: '30%', cy: '28%', labelPos: 'top',    activeAtStep: 2, completedAfterStep: 2 },
  { id: 'patch',   label: 'Developer',    cx: '30%', cy: '72%', labelPos: 'bottom', activeAtStep: 3, completedAfterStep: 3 },
  { id: 'audit',   label: 'Auditor',      cx: '50%', cy: '50%', labelPos: 'bottom', activeAtStep: 4, completedAfterStep: 4 },
  { id: 'deploy',  label: 'Re-verify',    cx: '75%', cy: '50%', labelPos: 'bottom', activeAtStep: 5, completedAfterStep: 5 },
  { id: 'secure',  label: 'Release',      cx: '90%', cy: '50%', labelPos: 'bottom', activeAtStep: 6, completedAfterStep: 6 },
];

interface Props {
  simulationStep?: number;
}

export function BottomTimeline({ simulationStep = 0 }: Props) {
  const resolveStatus = (node: PipelineNode): NodeStatus => {
    if (simulationStep > node.completedAfterStep) return 'completed';
    if (simulationStep === node.activeAtStep)      return 'active';
    return 'pending';
  };

  const currentNodes = PIPELINE.map((node) => ({
    ...node,
    status: resolveStatus(node),
  }));

  return (
    <div className="glass-panel w-full h-[80px] rounded-xl border border-white/10 relative flex flex-col p-2">
      <div className="flex-1 bg-black/20 rounded-lg relative overflow-hidden border border-white/5">
        {/* Static SVG tracks — no glow filters, no motion animations (perf) */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none z-0">
          {/* Base tracks (dim) */}
          <line x1="10%" y1="50%" x2="30%" y2="28%" stroke="rgba(255,255,255,0.08)" strokeWidth="1.5" />
          <line x1="10%" y1="50%" x2="30%" y2="72%" stroke="rgba(255,255,255,0.08)" strokeWidth="1.5" />
          <line x1="30%" y1="28%" x2="50%" y2="50%" stroke="rgba(255,255,255,0.08)" strokeWidth="1.5" />
          <line x1="30%" y1="72%" x2="50%" y2="50%" stroke="rgba(255,255,255,0.08)" strokeWidth="1.5" />
          <line x1="50%" y1="50%" x2="75%" y2="50%" stroke="rgba(255,255,255,0.08)" strokeWidth="1.5" />
          <line x1="75%" y1="50%" x2="90%" y2="50%" stroke="rgba(255,255,255,0.08)" strokeWidth="1.5" />

          {/* Active tracks — solid emerald when step is reached (no animation) */}
          {simulationStep >= 2 && <line x1="10%" y1="50%" x2="30%" y2="28%" stroke="#34d399" strokeWidth="2" />}
          {simulationStep >= 3 && <line x1="10%" y1="50%" x2="30%" y2="72%" stroke="#34d399" strokeWidth="2" />}
          {simulationStep >= 4 && <line x1="30%" y1="28%" x2="50%" y2="50%" stroke="#34d399" strokeWidth="2" />}
          {simulationStep >= 4 && <line x1="30%" y1="72%" x2="50%" y2="50%" stroke="#34d399" strokeWidth="2" />}
          {simulationStep >= 5 && <line x1="50%" y1="50%" x2="75%" y2="50%" stroke="#34d399" strokeWidth="2" />}
          {simulationStep >= 6 && <line x1="75%" y1="50%" x2="90%" y2="50%" stroke="#34d399" strokeWidth="2" />}
        </svg>

        {/* Pipeline nodes — no infinite pulse rings (perf) */}
        {currentNodes.map((node) => {
          const isCompleted = node.status === 'completed';
          const isActive    = node.status === 'active';

          return (
            <div
              key={node.id}
              className="absolute flex flex-col items-center justify-center -translate-x-1/2 -translate-y-1/2 z-10"
              style={{ left: node.cx, top: node.cy }}
            >
              {/* Top label */}
              {node.labelPos === 'top' && (
                <div className={cn("absolute text-[10px] font-medium whitespace-nowrap",
                  isActive    ? "bottom-[20px] text-emerald-400" :
                  isCompleted ? "bottom-[16px] text-slate-500" :
                                "bottom-[16px] text-slate-600"
                )}>
                  {node.label}
                </div>
              )}

              {/* Node circle — static, no pulse */}
              <div className={cn(
                "rounded-full flex items-center justify-center transition-colors duration-300",
                isActive    ? "w-3 h-3 bg-emerald-400" :
                isCompleted ? "w-2.5 h-2.5 bg-emerald-600" :
                              "w-2 h-2 bg-slate-600"
              )} />

              {/* Bottom label */}
              {node.labelPos === 'bottom' && (
                <div className={cn("absolute text-[10px] font-medium whitespace-nowrap",
                  isActive    ? "top-[20px] text-emerald-400" :
                  isCompleted ? "top-[16px] text-slate-500" :
                                "top-[16px] text-slate-600"
                )}>
                  {node.label}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
