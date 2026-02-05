import React, { useState, useEffect, useRef } from 'react';
import { TerminalLine } from '../types';
import { Maximize2, Minimize2 } from 'lucide-react';

interface TerminalProps {
  history: TerminalLine[];
  onCommand: (cmd: string) => void;
  isProcessing: boolean;
  isMaximized: boolean;
  onToggleMaximize: () => void;
}

const Terminal: React.FC<TerminalProps> = ({ history, onCommand, isProcessing, isMaximized, onToggleMaximize }) => {
  const [input, setInput] = useState('');
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  // Keep focus on input
  const handleClick = () => {
    inputRef.current?.focus();
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isProcessing) return;
    onCommand(input);
    setInput('');
  };

  return (
    <div 
      className="flex flex-col h-full bg-[#0c0c0c] border border-gray-800 rounded shadow-[0_0_20px_rgba(0,0,0,0.8)] overflow-hidden font-mono text-sm"
      onClick={handleClick}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-[#1a1a1a] border-b border-gray-800 select-none">
        <div className="flex items-center gap-2 text-gray-500">
          <span className="text-[10px]">root@kali: ~</span>
        </div>
        <div className="flex items-center gap-3">
             <button 
                onClick={(e) => { e.stopPropagation(); onToggleMaximize(); }}
                className="text-gray-500 hover:text-white transition-colors"
             >
                {isMaximized ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
             </button>
            <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-[#333] hover:bg-red-500/80 transition-colors"></div>
                <div className="w-2.5 h-2.5 rounded-full bg-[#333] hover:bg-yellow-500/80 transition-colors"></div>
                <div className="w-2.5 h-2.5 rounded-full bg-[#333] hover:bg-green-500/80 transition-colors"></div>
            </div>
        </div>
      </div>

      {/* Output Area */}
      <div className="flex-1 p-3 overflow-y-auto space-y-0.5 text-[#e5e5e5] cursor-text">
        <div className="text-gray-500 mb-2 font-tech">
          Kali GNU/Linux Rolling [Version 2025.1]<br/>
          (c) 2025 Offensive Security. All rights reserved.<br/>
          <br/>
          System Status: <span className="text-green-500">ONLINE</span><br/>
          Uplink: <span className="text-green-500">SECURE</span><br/>
        </div>
        
        {history.map((line, idx) => (
          <div key={idx} className="break-words">
            {line.type === 'input' ? (
              <div className="mt-2 mb-1">
                <span className="text-blue-500 font-bold">┌──(root💀kali)-[~]</span><br/>
                <span className="text-blue-500 font-bold">└─#</span> <span className="text-white">{line.content}</span>
              </div>
            ) : line.type === 'error' ? (
               <div className="text-red-400 whitespace-pre-wrap font-tech">{line.content}</div>
            ) : line.type === 'system' ? (
               <div className="text-purple-400 border-l-2 border-purple-500 pl-2 my-2 py-1 bg-purple-900/10 font-tech text-xs">
                  {line.content}
               </div>
            ) : (
              <div className="text-[#33ff33] text-glow whitespace-pre-wrap font-mono text-xs leading-relaxed opacity-90">
                {line.content}
              </div>
            )}
          </div>
        ))}
        
        {isProcessing && (
           <div className="mt-2 text-gray-500 animate-pulse">
             <span className="text-blue-500 font-bold">┌──(root💀kali)-[~]</span><br/>
             <span className="text-blue-500 font-bold">└─#</span> <span className="inline-block w-2 h-4 bg-gray-500 align-middle ml-1"></span>
           </div>
        )}

        {/* Active Input Line */}
        {!isProcessing && (
          <form onSubmit={handleSubmit} className="mt-2 flex flex-col">
             <div><span className="text-blue-500 font-bold">┌──(root💀kali)-[~]</span></div>
             <div className="flex items-center">
                <span className="text-blue-500 font-bold mr-2">└─#</span>
                <input
                    ref={inputRef}
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    className="flex-1 bg-transparent border-none outline-none text-white placeholder-gray-700"
                    autoFocus
                    autoComplete="off"
                    spellCheck="false"
                />
             </div>
          </form>
        )}
        
        <div ref={bottomRef} className="h-4" />
      </div>
    </div>
  );
};

export default Terminal;