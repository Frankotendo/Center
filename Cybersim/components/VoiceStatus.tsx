import React from 'react';
import { Mic, Volume2 } from 'lucide-react';

interface VoiceStatusProps {
  isPlaying: boolean;
}

const VoiceStatus: React.FC<VoiceStatusProps> = ({ isPlaying }) => {
  return (
    <div className="flex items-center gap-2 bg-gray-900 px-3 py-1.5 rounded-full border border-gray-800">
      <div className={`relative flex items-center justify-center w-6 h-6 rounded-full ${isPlaying ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-500'}`}>
        <Volume2 size={14} />
        {isPlaying && (
          <span className="absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75 animate-ping"></span>
        )}
      </div>
      <div className="flex flex-col">
        <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">AI Instructor</span>
        <span className={`text-xs font-mono leading-none ${isPlaying ? 'text-purple-400' : 'text-gray-600'}`}>
          {isPlaying ? 'SPEAKING...' : 'STANDBY'}
        </span>
      </div>
      
      {isPlaying && (
        <div className="flex gap-0.5 items-end h-4 ml-1">
          <div className="w-1 bg-purple-500 animate-[bounce_1s_infinite] h-2"></div>
          <div className="w-1 bg-purple-500 animate-[bounce_1.2s_infinite] h-3"></div>
          <div className="w-1 bg-purple-500 animate-[bounce_0.8s_infinite] h-2"></div>
        </div>
      )}
    </div>
  );
};

export default VoiceStatus;
