import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Key, X } from 'lucide-react';
import { TopCommandBar } from './components/TopCommandBar';
import { LeftPanelTopology } from './components/LeftPanelTopology';
import { CenterLiveTerminal } from './components/CenterLiveTerminal';
import { RightPanelDiffViewer } from './components/RightPanelDiffViewer';
import { BottomTimeline } from './components/BottomTimeline';
import { cn } from './lib/utils';

// --- Type: mirrors db.get_full_state() exactly ---
export interface SwarmState {
  active_agent: string;
  timeline_step: number;
  target_file: string;
  code_before: string;
  code_after: string;
  exploit_status: string;      // 'PENDING' | 'TESTING' | 'ACTIVE' | 'BLOCKED'
  patch_status: string;        // 'PENDING' | 'APPLIED' | 'SYNTAX_OK' | 'FAILED_AUDIT' | 'VERIFIED'
  confidence: number;          // 0-100
  signature_type: string;      // e.g. 'ZERO-DAY (SQL Injection)'
  root_cause: string;
  fix_applied: string;
  security_impact: string;
  waf_rule_file: string;
  deploy_status: string;       // 'PENDING' | 'READY' | 'DEPLOYED' | 'AWAITING_APPROVAL' | 'REJECTED'
  metrics: {
    critical: number;
    success_rate: string;
    active_agents: string;
    mttr_seconds: number;
    mttr_display: string;
  };
  logs: { time: string; agent: string; msg: string; status: string }[];
}

const INITIAL_STATE: SwarmState = {
  active_agent: 'IDLE',
  timeline_step: 0,
  target_file: '',
  code_before: '// Awaiting target assignment from Triage...',
  code_after: '// Awaiting patch from Developer agent...',
  exploit_status: 'PENDING',
  patch_status: 'PENDING',
  confidence: 0,
  signature_type: 'UNKNOWN',
  root_cause: '',
  fix_applied: '',
  security_impact: '',
  waf_rule_file: '',
  deploy_status: 'PENDING',
  metrics: {
    critical: 0,
    success_rate: 'N/A',
    active_agents: '5/5',
    mttr_seconds: 0,
    mttr_display: '---',
  },
  logs: [],
};

export default function App() {
  const [isLightMode, setIsLightMode] = useState(false);
  const [swarm, setSwarm] = useState<SwarmState>(INITIAL_STATE);
  
  // Admin API key configuration for authenticated endpoints
  const [adminApiKey, setAdminApiKey] = useState(() => localStorage.getItem('ensemble_admin_api_key') || '');
  const [showSettings, setShowSettings] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState(adminApiKey);

  useEffect(() => {
    document.body.classList.toggle('light-mode', isLightMode);
  }, [isLightMode]);

  // WebSocket: live connection to FastAPI /ws endpoint, auto-reconnects
  useEffect(() => {
    let ws: WebSocket;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      let wsUrl =
        window.location.port === '3000' || window.location.port === '5173'
          ? `ws://${window.location.hostname}:8501/ws`
          : `ws://${window.location.host}/ws`;

      if (adminApiKey) {
        wsUrl += `?api_key=${encodeURIComponent(adminApiKey)}`;
      }

      ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const data: Partial<SwarmState> = JSON.parse(event.data);
          // Merge incoming data — only override fields that arrived
          setSwarm((prev) => ({ ...prev, ...data }));
        } catch (err) {
          console.error('Failed to parse WebSocket message', err);
        }
      };

      ws.onclose = (event) => {
        if (event.code === 4401) {
          console.error('WebSocket connection rejected: unauthorized.');
        } else {
          console.warn('WebSocket disconnected. Reconnecting in 2s...');
          reconnectTimer = setTimeout(connect, 2000);
        }
      };

      ws.onerror = () => ws.close();
    };

    connect();
    return () => {
      ws?.close();
      clearTimeout(reconnectTimer);
    };
  }, [adminApiKey]);

  // Human-in-the-loop approval triggers
  const handleApprove = async () => {
    try {
      const baseUrl =
        window.location.port === '3000' || window.location.port === '5173'
          ? `http://${window.location.hostname}:8501`
          : '';
      const response = await fetch(`${baseUrl}/approve`, {
        method: 'POST',
        headers: adminApiKey ? { 'X-API-Key': adminApiKey } : {},
      });
      if (!response.ok) {
        const err = await response.json();
        alert(`Failed to approve: ${err.error || response.statusText}`);
      }
    } catch (err) {
      console.error(err);
      alert(`Network error during approval: ${err}`);
    }
  };

  const handleReject = async () => {
    try {
      const baseUrl =
        window.location.port === '3000' || window.location.port === '5173'
          ? `http://${window.location.hostname}:8501`
          : '';
      const response = await fetch(`${baseUrl}/reject`, {
        method: 'POST',
        headers: adminApiKey ? { 'X-API-Key': adminApiKey } : {},
      });
      if (!response.ok) {
        const err = await response.json();
        alert(`Failed to reject: ${err.error || response.statusText}`);
      }
    } catch (err) {
      console.error(err);
      alert(`Network error during rejection: ${err}`);
    }
  };

  const handleSaveApiKey = (e: React.FormEvent) => {
    e.preventDefault();
    localStorage.setItem('ensemble_admin_api_key', apiKeyInput);
    setAdminApiKey(apiKeyInput);
    setShowSettings(false);
  };

  return (
    <div className="h-screen w-screen bg-[var(--color-bg-base)] text-[var(--color-text-slate)] font-sans flex flex-col p-6 gap-6 overflow-hidden relative selection:bg-[var(--color-brand)] selection:text-white transition-colors duration-500">
      
      {/* Ambient background — single orb, static (no animate-pulse) */}
      <div className="absolute inset-0 pointer-events-none z-0">
        <div className="absolute top-[20%] left-[30%] w-[50%] h-[50%] rounded-full blur-[60px] mix-blend-screen bg-emerald-500/15"></div>
      </div>

      {/* App Content — no entrance blur animation (perf) */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4 }}
        className="z-10 flex flex-col h-full w-full gap-4 max-w-[1920px] mx-auto"
      >
        {/* Header row — reduced from 140px to 80px */}
        <div className="flex gap-4 shrink-0 h-[80px] w-full items-stretch">

          {/* Brand panel — consistent with other panels (rounded-xl, px-6) */}
          <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, ease: "easeOut" }} className="glass-panel w-fit shrink-0 rounded-xl flex items-center justify-between px-6 gap-6 relative overflow-hidden">
            <div className="z-10 flex w-full justify-between items-center gap-6">
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white whitespace-nowrap">
                  Ensemble<span className="ml-1 text-emerald-400">AI</span>
                </h1>
                <p className="text-[11px] tracking-wide text-slate-400 mt-0.5">
                  DevSecOps Pipeline
                </p>
              </div>

              {/* Toggles */}
              <div className="flex items-center gap-3 shrink-0">
                {/* Admin key configure button */}
                <button
                  onClick={() => {
                    setApiKeyInput(adminApiKey);
                    setShowSettings(true);
                  }}
                  className="w-10 h-10 rounded-full flex items-center justify-center cursor-pointer transition-all hover:bg-[var(--color-border-panel)]/10 text-white/80 hover:text-white"
                  title="Configure Admin API Key"
                >
                  <Key size={18} className={adminApiKey ? "text-emerald-400" : "text-white/60"} />
                </button>

                <button
                  onClick={() => setIsLightMode(!isLightMode)}
                  className="w-[64px] shrink-0 h-[32px] rounded-full flex items-center cursor-pointer relative shadow-inner overflow-hidden group/toggle backdrop-blur-md bg-[var(--color-border-panel)]/10 border border-[var(--color-border-panel)]/20 text-black dark:text-white"
                  title="Toggle Theme"
                >
                  <span className={cn(
                    "absolute w-[26px] h-[26px] rounded-full shadow-[0_2px_10px_rgba(0,0,0,0.8)] transition-transform duration-500 ease-[cubic-bezier(0.34,1.56,0.64,1)] z-10 border border-[var(--color-border-panel)]/10",
                    isLightMode ? "bg-white translate-x-[34px]" : "bg-black/50 translate-x-[3px]"
                  )}></span>
                  <div className="absolute inset-0 flex justify-between items-center px-[8px] pointer-events-none z-0">
                    <span className="text-[12px] leading-none drop-shadow-md select-none opacity-80 group-hover/toggle:opacity-100 transition-opacity">🌙</span>
                    <span className="text-[12px] leading-none drop-shadow-md select-none opacity-80 group-hover/toggle:opacity-100 transition-opacity">☀️</span>
                  </div>
                </button>
              </div>
            </div>
          </motion.div>
          
          {/* Swarm status bar */}
          <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.1, ease: "easeOut" }} className="flex-1 drop-shadow-2xl h-full min-w-0">
            <TopCommandBar
              activeAgent={swarm.active_agent}
              metrics={swarm.metrics}
            />
          </motion.div>
        </div>

        {/* Main 3-column body */}
        <div className="flex flex-col xl:flex-row flex-1 gap-5 overflow-y-auto xl:overflow-hidden min-h-0 drop-shadow-2xl pb-4 xl:pb-0 items-stretch">
          <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.6, delay: 0.2, ease: "easeOut" }} className="flex w-full xl:w-[280px] 2xl:w-[320px] h-[400px] xl:h-auto shrink-0">
            <LeftPanelTopology
              simulationStep={swarm.timeline_step}
              activeAgent={swarm.active_agent}
            />
          </motion.div>
          <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.3, ease: "easeOut" }} className="flex flex-1 w-full h-[500px] xl:h-auto min-w-0">
            <CenterLiveTerminal
              liveLogs={swarm.logs}
              exploitStatus={swarm.exploit_status}
              patchStatus={swarm.patch_status}
              confidence={swarm.confidence}
              signatureType={swarm.signature_type}
            />
          </motion.div>
          <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.6, delay: 0.4, ease: "easeOut" }} className="flex w-full xl:w-[380px] 2xl:w-[480px] h-[600px] xl:h-auto shrink-0">
            <RightPanelDiffViewer
              codeBefore={swarm.code_before}
              codeAfter={swarm.code_after}
              targetFile={swarm.target_file}
              rootCause={swarm.root_cause}
              fixApplied={swarm.fix_applied}
              securityImpact={swarm.security_impact}
              wafRuleFile={swarm.waf_rule_file}
              deployStatus={swarm.deploy_status}
              onApprove={handleApprove}
              onReject={handleReject}
            />
          </motion.div>
        </div>

        {/* Bottom pipeline timeline */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.5, ease: "easeOut" }} className="shrink-0 drop-shadow-2xl">
          <BottomTimeline simulationStep={swarm.timeline_step} />
        </motion.div>
      </motion.div>

      {/* Settings Modal (Admin API key) */}
      <AnimatePresence>
        {showSettings && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="glass-panel w-full max-w-md p-6 overflow-hidden rounded-2xl border border-white/10 bg-slate-900/90 shadow-2xl relative animate-none"
            >
              <button
                onClick={() => setShowSettings(false)}
                className="absolute top-4 right-4 text-slate-400 hover:text-white transition-colors cursor-pointer"
              >
                <X size={20} />
              </button>
              
              <h2 className="text-lg font-bold tracking-tight text-white mb-4">
                Configure Admin Credentials
              </h2>
              
              <form onSubmit={handleSaveApiKey} className="flex flex-col gap-4">
                <div className="flex flex-col gap-1.5">
                  <label className="text-xs font-mono tracking-wider text-slate-400 uppercase">
                    Admin API Key (ENSEMBLE_ADMIN_API_KEY)
                  </label>
                  <input
                    type="password"
                    value={apiKeyInput}
                    onChange={(e) => setApiKeyInput(e.target.value)}
                    placeholder="Enter API key configured in backend env"
                    className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:border-emerald-400 transition-colors font-mono"
                  />
                  <p className="text-[10px] text-slate-500 leading-normal mt-1">
                    Required if the FastAPI backend was initialized with the <code>ENSEMBLE_ADMIN_API_KEY</code> environment variable. Leave blank if running in public dev mode.
                  </p>
                </div>
                
                <div className="flex gap-3 justify-end mt-2">
                  <button
                    type="button"
                    onClick={() => setShowSettings(false)}
                    className="px-4 py-2 rounded-lg text-sm text-slate-300 hover:text-white transition-colors cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-5 py-2 rounded-lg text-sm bg-emerald-500 hover:bg-emerald-600 text-white font-semibold transition-colors cursor-pointer"
                  >
                    Save Changes
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
