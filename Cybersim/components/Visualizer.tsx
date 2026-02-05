import React from 'react';
import { Target, TargetType } from '../types';
import { Server, Wifi, ShieldAlert, Lock, Unlock, Database, Globe, Smartphone, Activity, Crosshair, Binary, Maximize2, Minimize2, Cpu } from 'lucide-react';

interface VisualizerProps {
  target: Target | null;
  isMaximized: boolean;
  onToggleMaximize: () => void;
}

const Visualizer: React.FC<VisualizerProps> = ({ target, isMaximized, onToggleMaximize }) => {
  if (!target) {
    return (
      <div className="h-full flex flex-col items-center justify-center bg-[#050505] border border-gray-800 rounded relative overflow-hidden group">
         <div className="absolute top-2 right-2 z-50">
            <button onClick={onToggleMaximize} className="text-gray-600 hover:text-white transition-colors p-2">
                {isMaximized ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
            </button>
         </div>
         <div className="absolute inset-0 opacity-10 bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')]"></div>
         <div className="z-10 flex flex-col items-center text-gray-600">
            <Activity className="animate-pulse mb-4 text-gray-700" size={64} />
            <p className="font-tech text-lg tracking-widest uppercase">Awaiting Target Designation</p>
         </div>
      </div>
    );
  }

  const isCompromised = target.status === 'compromised';
  const statusColor = isCompromised ? 'text-red-500' : 'text-emerald-500';
  const borderColor = isCompromised ? 'border-red-500/30' : 'border-emerald-500/30';

  return (
    <div className="h-full flex flex-col bg-[#080808] border border-gray-800 rounded relative overflow-hidden font-tech">
      
      {/* Decorative Grid Background */}
      <div className="absolute inset-0 z-0 opacity-20 pointer-events-none" 
           style={{ 
             background: `
                linear-gradient(to right, #111 1px, transparent 1px),
                linear-gradient(to bottom, #111 1px, transparent 1px)
             `,
             backgroundSize: '40px 40px'
           }}>
      </div>
      
      {/* HUD Header */}
      <div className="z-10 flex justify-between items-start p-6 border-b border-gray-800/50 bg-black/20 backdrop-blur-sm">
        <div>
           <div className="flex items-center gap-2 text-blue-400/80 mb-1">
             <Crosshair size={14} className="animate-spin-slow" />
             <span className="text-[10px] uppercase tracking-[0.2em]">Target Lock</span>
           </div>
           <h2 className="text-3xl font-bold text-white tracking-tight uppercase glitch-text">{target.name}</h2>
           <div className="flex items-center gap-3 mt-2 font-mono text-xs text-gray-400">
             <span className="px-1 bg-gray-800 text-gray-300 rounded-sm">IP: {target.ip}</span>
             <span className="px-1 bg-gray-800 text-gray-300 rounded-sm">OS: {target.os}</span>
           </div>
        </div>
        <div className="flex items-start gap-4">
            <div className={`px-4 py-2 rounded border ${borderColor} ${statusColor} bg-black/40 backdrop-blur`}>
            <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${isCompromised ? 'bg-red-500 animate-ping' : 'bg-emerald-500'}`}></div>
                <span className="font-bold tracking-widest text-sm">{target.status.toUpperCase()}</span>
            </div>
            </div>
            <button onClick={onToggleMaximize} className="text-gray-500 hover:text-white transition-colors mt-1">
                {isMaximized ? <Minimize2 size={18} /> : <Maximize2 size={18} />}
            </button>
        </div>
      </div>

      {/* Main Radar View */}
      <div className="flex-1 z-10 relative flex items-center justify-center overflow-hidden">
         {/* Radar Rings */}
         <div className={`absolute w-80 h-80 rounded-full border ${borderColor} opacity-20`}></div>
         <div className={`absolute w-60 h-60 rounded-full border ${borderColor} opacity-30`}></div>
         <div className={`absolute w-40 h-40 rounded-full border ${borderColor} opacity-40`}></div>
         
         {/* Scanning Line */}
         <div className="absolute w-80 h-80 rounded-full animate-[spin_4s_linear_infinite] opacity-30 pointer-events-none bg-gradient-to-tr from-transparent via-transparent to-emerald-500/50"></div>

         {/* Central Icon */}
         <div className={`relative z-20 p-6 rounded-full border-2 ${borderColor} bg-black/80 backdrop-blur-md shadow-[0_0_30px_rgba(0,0,0,0.5)]`}>
             <TargetMainIcon type={target.type} size={48} className={isCompromised ? 'text-red-500' : 'text-blue-400'} />
             
             {/* Orbital Ports */}
             {target.ports.map((port, idx) => {
               const angle = (idx / (Math.max(target.ports.length, 1))) * 2 * Math.PI;
               const radius = 140; 
               const x = Math.cos(angle) * radius;
               const y = Math.sin(angle) * radius;
               
               return (
                 <div 
                   key={port}
                   className="absolute top-1/2 left-1/2 w-0 h-0 flex items-center justify-center"
                   style={{ transform: `translate(${x}px, ${y}px)` }}
                 >
                   <div className="relative group">
                     <div className="w-3 h-3 bg-black border border-emerald-500/50 rounded-full"></div>
                     <div className="absolute top-4 left-1/2 -translate-x-1/2 bg-black/80 text-emerald-400 text-[10px] px-1 border border-emerald-900 rounded whitespace-nowrap">
                        Port {port}
                     </div>
                     <div className="absolute top-1/2 left-1/2 w-24 h-[1px] bg-emerald-500/20 origin-left -z-10" 
                          style={{ transform: `rotate(${angle + Math.PI}rad) translateX(6px)` }}></div>
                   </div>
                 </div>
               );
             })}
         </div>
      </div>

      {/* Vulnerability Footer */}
      <div className="z-10 bg-black/60 border-t border-gray-800 p-4 backdrop-blur-md">
        <div className="flex items-center gap-2 mb-3 text-gray-500">
           <Binary size={14} />
           <h3 className="text-xs font-bold uppercase tracking-widest">Threat Intelligence</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {target.vulnerabilities.length === 0 ? (
             <div className="col-span-full text-center py-2 text-gray-600 text-xs font-mono border border-dashed border-gray-800">
                // SCANNING FOR VULNERABILITIES...
             </div>
          ) : (
            target.vulnerabilities.map((vuln, i) => (
              <div key={i} className="flex items-center gap-2 px-3 py-2 bg-red-950/20 border border-red-900/50 rounded text-xs text-red-400 font-mono">
                <ShieldAlert size={12} className="shrink-0" />
                <span className="truncate">{vuln}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

const TargetMainIcon = ({ type, size, className }: { type: string, size: number, className?: string }) => {
   switch (type) {
    case TargetType.WEBSITE: return <Globe size={size} className={className} />;
    case TargetType.DATABASE: return <Database size={size} className={className} />;
    case TargetType.IPHONE: case TargetType.ANDROID: return <Smartphone size={size} className={className} />;
    case TargetType.WIFI: return <Wifi size={size} className={className} />;
    case TargetType.IOT: return <Cpu size={size} className={className} />;
    default: return <Server size={size} className={className} />;
  }
}

export default Visualizer;