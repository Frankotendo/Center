import React from 'react';
import { Mission, Target, TargetType } from '../types';
import { Shield, Target as TargetIcon, CheckCircle, Lock, Server, Smartphone, Globe, Database, Cpu, ChevronRight, Maximize2, Minimize2, Wifi, Blocks } from 'lucide-react';

interface MissionHubProps {
  missions: Mission[];
  currentMissionId: string | null;
  onSelectMission: (id: string) => void;
  targets: Record<string, Target>;
  isMaximized: boolean;
  onToggleMaximize: () => void;
}

const TargetTypeIcon = ({ type }: { type: string }) => {
  switch (type) {
    case TargetType.IPHONE:
    case TargetType.ANDROID: return <Smartphone size={14} />;
    case TargetType.WEBSITE: return <Globe size={14} />;
    case TargetType.DATABASE: return <Database size={14} />;
    case TargetType.IOT: return <Cpu size={14} />;
    case TargetType.WIFI: return <Wifi size={14} />;
    case TargetType.BLOCKCHAIN: return <Blocks size={14} />;
    default: return <Server size={14} />;
  }
};

const MissionHub: React.FC<MissionHubProps> = ({ missions, currentMissionId, onSelectMission, targets, isMaximized, onToggleMaximize }) => {
  return (
    <div className="h-full flex flex-col bg-[#080808] border border-gray-800 rounded p-4 font-tech overflow-hidden">
      <div className="flex items-center justify-between mb-6 pb-2 border-b border-gray-800">
        <div className="flex items-center gap-2 text-purple-500">
          <Shield size={18} />
          <h2 className="text-sm font-bold tracking-[0.2em] uppercase">Operations</h2>
        </div>
        <div className="flex items-center gap-3">
            <span className="text-[10px] text-gray-600">{missions.filter(m => m.completed).length}/{missions.length} COMPLETED</span>
            <button onClick={onToggleMaximize} className="text-gray-500 hover:text-white transition-colors">
                {isMaximized ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
            </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto pr-2 space-y-3 custom-scrollbar">
        {missions.map((mission) => {
          const isCurrent = mission.id === currentMissionId;
          const target = targets[mission.targetId];
          
          return (
            <div 
              key={mission.id}
              onClick={() => onSelectMission(mission.id)}
              className={`
                group relative p-4 border transition-all duration-200 cursor-pointer overflow-hidden
                ${isCurrent 
                  ? 'bg-purple-900/10 border-purple-500/50 shadow-[0_0_15px_rgba(168,85,247,0.1)]' 
                  : mission.completed 
                    ? 'bg-gray-900/20 border-green-900/30 opacity-60 hover:opacity-100' 
                    : 'bg-gray-900/20 border-gray-800 hover:border-gray-600 hover:bg-gray-800/40'
                }
              `}
            >
              {/* Decoration Corner */}
              <div className={`absolute top-0 right-0 w-0 h-0 border-l-[20px] border-l-transparent border-t-[20px] ${isCurrent ? 'border-t-purple-500' : 'border-t-gray-700'} transition-colors`}></div>

              <div className="flex justify-between items-start mb-2 relative z-10">
                <h3 className={`font-bold text-sm tracking-wide ${isCurrent ? 'text-white' : 'text-gray-400 group-hover:text-gray-200'}`}>
                  {mission.title}
                </h3>
                {mission.completed ? (
                  <CheckCircle size={14} className="text-green-600" />
                ) : (
                  <span className={`text-[9px] px-1.5 py-0.5 border ${
                    mission.difficulty === 'Beginner' ? 'border-green-900 text-green-500' :
                    mission.difficulty === 'Intermediate' ? 'border-yellow-900 text-yellow-500' :
                    'border-red-900 text-red-500'
                  }`}>
                    {mission.difficulty.toUpperCase()}
                  </span>
                )}
              </div>
              
              <p className="text-[11px] text-gray-500 mb-3 leading-relaxed font-mono">{mission.description}</p>
              
              <div className="flex items-center justify-between mt-auto">
                {target && (
                    <div className="flex items-center gap-1.5 text-[10px] text-gray-400 bg-black/40 px-2 py-1 border border-gray-800">
                    <TargetTypeIcon type={target.type} />
                    <span className="truncate max-w-[100px]">{target.name}</span>
                    </div>
                )}
                
                {isCurrent && <ChevronRight size={14} className="text-purple-500 animate-pulse" />}
              </div>
              
              {isCurrent && (
                <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-gradient-to-b from-purple-500 to-transparent"></div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default MissionHub;