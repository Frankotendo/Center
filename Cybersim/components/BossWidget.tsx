import React, { useState, useEffect, useCallback } from 'react';
import { Mic, MicOff, Volume2, Radio } from 'lucide-react';

interface BossWidgetProps {
  onVoiceCommand: (text: string) => void;
  isProcessing: boolean;
  isSpeaking: boolean;
}

const BossWidget: React.FC<BossWidgetProps> = ({ onVoiceCommand, isProcessing, isSpeaking }) => {
  const [isListening, setIsListening] = useState(false);
  const [isSupported, setIsSupported] = useState(true);
  const [recognition, setRecognition] = useState<any>(null);

  useEffect(() => {
    if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
      const SpeechRecognition = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
      const recognizer = new SpeechRecognition();
      recognizer.continuous = false;
      recognizer.interimResults = false;
      recognizer.lang = 'en-US';

      recognizer.onstart = () => setIsListening(true);
      recognizer.onend = () => setIsListening(false);
      recognizer.onerror = (event: any) => {
        console.error("Speech recognition error", event.error);
        setIsListening(false);
      };
      recognizer.onresult = (event: any) => {
        const transcript = event.results[0][0].transcript;
        if (transcript) {
          onVoiceCommand(transcript);
        }
      };

      setRecognition(recognizer);
    } else {
      setIsSupported(false);
    }
  }, [onVoiceCommand]);

  const toggleListening = useCallback(() => {
    if (!recognition) return;

    if (isListening) {
      recognition.stop();
    } else {
      try {
        recognition.start();
      } catch (e) {
        console.error("Failed to start recognition", e);
      }
    }
  }, [recognition, isListening]);

  if (!isSupported) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 flex items-end gap-4">
        
      {/* Speech Bubble / Status (Appears when active) */}
      {(isSpeaking || isListening || isProcessing) && (
          <div className="mb-4 bg-black/80 backdrop-blur-md border border-purple-500/50 p-3 rounded-lg text-sm font-mono text-purple-200 shadow-xl max-w-[200px] animate-in slide-in-from-bottom-5 fade-in duration-300">
              {isProcessing ? (
                  <span className="flex items-center gap-2"><span className="w-2 h-2 bg-purple-500 rounded-full animate-bounce"></span> Processing...</span>
              ) : isListening ? (
                  <span className="text-red-400 font-bold">I am listening...</span>
              ) : isSpeaking ? (
                  <span className="flex items-center gap-2"><Volume2 size={12} className="animate-pulse"/> Oga is speaking...</span>
              ) : null}
          </div>
      )}

      {/* Main Avatar Container */}
      <div className="relative group">
          {/* Pulsing Rings */}
          {isSpeaking && (
             <>
                <div className="absolute inset-0 rounded-full bg-purple-600 opacity-20 animate-ping"></div>
                <div className="absolute -inset-2 rounded-full bg-purple-600 opacity-10 animate-ping delay-100"></div>
             </>
          )}

          {/* Avatar Base */}
          <div className="w-20 h-20 rounded-full bg-gradient-to-b from-gray-800 to-black border-2 border-purple-500 shadow-[0_0_30px_rgba(168,85,247,0.4)] flex items-center justify-center relative overflow-hidden">
              
              {/* Scanline Overlay */}
              <div className="absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_4px,100%_100%] pointer-events-none z-20"></div>

              {/* Face/Icon */}
              {isListening ? (
                  <div className="text-red-500 animate-pulse">
                      <Mic size={32} />
                  </div>
              ) : (
                  <div className={`transition-all duration-300 ${isSpeaking ? 'scale-110 text-purple-300' : 'text-purple-600 grayscale opacity-80'}`}>
                      {/* Abstract Face - "The Boss" */}
                      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M12 2a8 8 0 0 1 8 8v3a4 4 0 0 1-4 4v0a4 4 0 0 1-4-4v-3" /> {/* Head shape modified */}
                          <path d="M8 12h8" /> {/* Glasses / Visor */}
                          <path d="M12 16v3" /> 
                          <path d="M8 22h8" /> {/* Shoulders */}
                      </svg>
                  </div>
              )}
          </div>

          {/* Mic Trigger Button (Overlay on hover or separate?) -> Let's make the avatar clickable or have a sub-button. 
              User asked for a button to trigger listen/speak. Let's make the whole avatar clickable. 
          */}
          <button 
             onClick={toggleListening}
             disabled={isProcessing}
             className="absolute inset-0 w-full h-full rounded-full z-30 cursor-pointer focus:outline-none focus:ring-2 focus:ring-purple-500/50"
             title="Talk to Oga Kore"
          >
          </button>

          {/* Online Indicator */}
          <div className="absolute bottom-1 right-1 w-4 h-4 bg-gray-900 rounded-full border border-gray-700 flex items-center justify-center z-40">
              <div className={`w-2 h-2 rounded-full ${isListening ? 'bg-red-500 animate-pulse' : 'bg-green-500'}`}></div>
          </div>
          
          {/* Label */}
          <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 whitespace-nowrap bg-black/90 text-[10px] text-purple-400 px-2 py-0.5 rounded border border-purple-900 font-tech tracking-wider opacity-0 group-hover:opacity-100 transition-opacity">
              DIRECTOR KORE
          </div>
      </div>
    </div>
  );
};

export default BossWidget;