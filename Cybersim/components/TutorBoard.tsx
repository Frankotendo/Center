import React, { useEffect, useState } from 'react';
import { Lecture, LectureStep } from '../types';
import { Maximize2, Minimize2, GraduationCap, ChevronRight, Play, Check, BookOpen } from 'lucide-react';

interface TutorBoardProps {
  lecture: Lecture | null;
  onNextStep: () => void;
  onStartLecture: (topic: string) => void;
  isMaximized: boolean;
  onToggleMaximize: () => void;
  isLoading: boolean;
  isPlayingAudio: boolean;
}

const TutorBoard: React.FC<TutorBoardProps> = ({ 
    lecture, 
    onNextStep, 
    onStartLecture,
    isMaximized, 
    onToggleMaximize, 
    isLoading,
    isPlayingAudio 
}) => {
  const [currentStep, setCurrentStep] = useState<LectureStep | null>(null);
  const [topicInput, setTopicInput] = useState('');

  useEffect(() => {
    if (lecture && lecture.steps[lecture.currentStepIndex]) {
      setCurrentStep(lecture.steps[lecture.currentStepIndex]);
    }
  }, [lecture]);

  const handleStartSubmit = (e: React.FormEvent) => {
      e.preventDefault();
      if (topicInput.trim()) {
          onStartLecture(topicInput);
          setTopicInput('');
      }
  };

  if (!lecture || !currentStep) {
    return (
      <div className="h-full flex flex-col bg-[#FDFBF7] border-8 border-[#3D2B1F] rounded-lg relative overflow-hidden shadow-2xl">
         {/* Controls Overlay */}
         <div className="absolute top-2 right-2 z-50">
            <button onClick={onToggleMaximize} className="text-gray-400 hover:text-emerald-700 transition-colors p-2 bg-white/50 rounded-full">
                {isMaximized ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
            </button>
         </div>

         <div className="flex-1 flex flex-col items-center justify-center p-8 text-center bg-[url('https://www.transparenttextures.com/patterns/dust.png')]">
             {isLoading ? (
                 <div className="flex flex-col items-center gap-4 text-gray-500">
                     <div className="w-12 h-12 border-4 border-gray-300 border-t-emerald-600 rounded-full animate-spin"></div>
                     <p className="font-hand text-2xl animate-pulse">Professor Cypher is preparing the curriculum...</p>
                 </div>
             ) : (
                <div className="max-w-md w-full">
                    <div className="mb-6 flex justify-center">
                        <div className="bg-emerald-100 p-4 rounded-full border-2 border-emerald-200">
                            <GraduationCap size={48} className="text-emerald-700" />
                        </div>
                    </div>
                    <h2 className="font-hand text-3xl font-bold text-gray-800 mb-2">Cyber Warfare Academy</h2>
                    <p className="font-hand text-xl text-gray-600 mb-8">
                        "Knowledge is the primary weapon. What shall we study today?"
                    </p>
                    
                    <form onSubmit={handleStartSubmit} className="relative">
                        <input 
                            type="text"
                            value={topicInput}
                            onChange={(e) => setTopicInput(e.target.value)}
                            placeholder="e.g., SQL Injection, WiFi Handshakes, Buffer Overflows..."
                            className="w-full px-5 py-3 rounded-lg border-2 border-gray-300 font-mono text-sm bg-white focus:outline-none focus:border-emerald-500 shadow-sm transition-colors text-gray-800"
                        />
                        <button 
                            type="submit"
                            disabled={!topicInput.trim()}
                            className="absolute right-2 top-1.5 bottom-1.5 bg-emerald-600 text-white px-4 rounded hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-bold text-xs uppercase tracking-wider flex items-center gap-2"
                        >
                            Learn <BookOpen size={14} />
                        </button>
                    </form>
                    
                    <div className="mt-8 grid grid-cols-2 gap-3 opacity-60">
                        <div className="text-xs font-mono bg-gray-100 p-2 rounded border border-gray-200">cmd: learn xss</div>
                        <div className="text-xs font-mono bg-gray-100 p-2 rounded border border-gray-200">cmd: learn nmap</div>
                    </div>
                </div>
             )}
         </div>
      </div>
    );
  }

  const progress = ((lecture.currentStepIndex + 1) / lecture.steps.length) * 100;

  return (
    <div className="h-full flex flex-col bg-[#FDFBF7] border-8 border-[#3D2B1F] rounded-lg relative overflow-hidden shadow-2xl">
      
      {/* Frame Screw Visuals */}
      <div className="absolute top-2 left-2 w-3 h-3 rounded-full bg-gray-400 border border-gray-600 shadow-inner z-20"></div>
      <div className="absolute top-2 right-2 w-3 h-3 rounded-full bg-gray-400 border border-gray-600 shadow-inner z-20"></div>
      <div className="absolute bottom-2 left-2 w-3 h-3 rounded-full bg-gray-400 border border-gray-600 shadow-inner z-20"></div>
      <div className="absolute bottom-2 right-2 w-3 h-3 rounded-full bg-gray-400 border border-gray-600 shadow-inner z-20"></div>

      {/* Header / Top Rail */}
      <div className="h-12 bg-[#2A1E16] flex items-center justify-between px-4 z-10 border-b-4 border-[#1F1610]">
        <div className="flex items-center gap-2">
            <div className="bg-emerald-700 p-1.5 rounded-full border border-emerald-500/30">
                <GraduationCap size={16} className="text-white" />
            </div>
            <h2 className="text-gray-200 font-mono text-sm tracking-wider uppercase truncate max-w-[200px]">
                Lecture: {lecture.topic}
            </h2>
        </div>
        <div className="flex items-center gap-3">
             <div className="flex flex-col items-end mr-2">
                 <span className="text-[10px] text-gray-400 font-mono">STEP {lecture.currentStepIndex + 1}/{lecture.steps.length}</span>
                 <div className="w-20 h-1 bg-gray-700 rounded-full overflow-hidden">
                     <div className="h-full bg-emerald-500 transition-all duration-500" style={{ width: `${progress}%` }}></div>
                 </div>
             </div>
             <button onClick={onToggleMaximize} className="text-gray-400 hover:text-white transition-colors">
                {isMaximized ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
             </button>
        </div>
      </div>

      {/* Whiteboard Surface */}
      <div className="flex-1 relative overflow-hidden bg-[url('https://www.transparenttextures.com/patterns/dust.png')]">
         <div className="absolute inset-0 p-8 overflow-y-auto custom-scrollbar">
            
            {/* Professor Avatar / Bubble */}
            <div className="absolute top-4 left-4 flex gap-3 items-start max-w-[80%] z-10">
                <div className={`
                    w-12 h-12 rounded-full border-2 border-emerald-800 bg-emerald-900 flex items-center justify-center shrink-0 shadow-lg
                    ${isPlayingAudio ? 'animate-[bounce_2s_infinite]' : ''}
                `}>
                    <span className="text-2xl">👨‍🏫</span>
                </div>
                {isPlayingAudio && (
                     <div className="bg-white p-3 rounded-tr-xl rounded-br-xl rounded-bl-xl shadow-md border border-gray-200 animate-pulse">
                        <div className="flex gap-1">
                            <span className="w-1 h-1 bg-gray-400 rounded-full animate-bounce"></span>
                            <span className="w-1 h-1 bg-gray-400 rounded-full animate-bounce delay-100"></span>
                            <span className="w-1 h-1 bg-gray-400 rounded-full animate-bounce delay-200"></span>
                        </div>
                     </div>
                )}
            </div>

            {/* Board Content */}
            <div className="mt-16 ml-2 font-hand text-2xl text-[#2d3748] leading-relaxed whitespace-pre-wrap">
                {currentStep.boardNotes}
            </div>

         </div>

         {/* Marker Tray / Controls */}
         <div className="absolute bottom-0 left-0 right-0 h-16 bg-[#e2e2e2] border-t-4 border-[#d4d4d4] shadow-[inset_0_2px_4px_rgba(0,0,0,0.1)] flex items-center justify-between px-6">
            
            <div className="flex gap-2 opacity-80 pointer-events-none">
                <div className="w-24 h-3 bg-red-600 rounded-full transform -rotate-1 shadow-sm"></div>
                <div className="w-24 h-3 bg-blue-600 rounded-full transform rotate-1 shadow-sm"></div>
                <div className="w-24 h-3 bg-black rounded-full transform -rotate-2 shadow-sm"></div>
                <div className="w-16 h-6 bg-gray-600 rounded shadow-sm ml-4 transform rotate-1 flex items-center justify-center text-[10px] text-white font-mono">ERASER</div>
            </div>

            <div className="flex items-center gap-4">
                <p className="text-gray-500 font-hand text-lg hidden md:block">
                    {isPlayingAudio ? "Listen to the professor..." : "Copy notes to terminal, then continue."}
                </p>
                <button 
                    onClick={onNextStep}
                    disabled={isPlayingAudio}
                    className={`
                        flex items-center gap-2 px-6 py-2 rounded shadow-md border-b-4 transition-all
                        ${isPlayingAudio 
                            ? 'bg-gray-300 text-gray-500 border-gray-400 cursor-not-allowed' 
                            : 'bg-emerald-600 text-white border-emerald-800 hover:bg-emerald-500 hover:border-emerald-700 active:border-b-0 active:translate-y-1'
                        }
                    `}
                >
                    {lecture.currentStepIndex === lecture.steps.length - 1 ? (
                        <>Finish Class <Check size={18} /></>
                    ) : (
                        <>Next Slide <ChevronRight size={18} /></>
                    )}
                </button>
            </div>
         </div>

      </div>
    </div>
  );
};

export default TutorBoard;