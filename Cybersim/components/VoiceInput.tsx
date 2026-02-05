
import React, { useState, useEffect, useCallback } from 'react';
import { Mic, MicOff, Radio } from 'lucide-react';

interface VoiceInputProps {
  onVoiceCommand: (text: string) => void;
  isProcessing: boolean;
  isSpeaking: boolean;
}

const VoiceInput: React.FC<VoiceInputProps> = ({ onVoiceCommand, isProcessing, isSpeaking }) => {
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
      // Stop speaking if AI is currently talking when user wants to talk
      if (isSpeaking) {
          // Ideally we would cancel audio here, but that requires lifting state up further. 
          // For now, the user just talks over it or waits.
      }
      try {
        recognition.start();
      } catch (e) {
        console.error("Failed to start recognition", e);
      }
    }
  }, [recognition, isListening, isSpeaking]);

  if (!isSupported) return null;

  return (
    <button
      onClick={toggleListening}
      disabled={isProcessing}
      className={`
        relative flex items-center justify-center w-12 h-12 rounded-full border-2 transition-all duration-300
        ${isListening 
          ? 'bg-red-900/80 border-red-500 text-white shadow-[0_0_15px_rgba(239,68,68,0.5)] scale-110' 
          : 'bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-500 hover:text-white'
        }
        ${isProcessing ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
      `}
      title="Push to Talk (Comms with Director Kore)"
    >
      {isListening ? (
        <>
          <Mic size={20} className="animate-pulse" />
          <span className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full animate-ping"></span>
        </>
      ) : (
        <MicOff size={20} />
      )}
      
      {/* Tooltip-ish label for context */}
      <div className="absolute -bottom-6 text-[10px] font-mono whitespace-nowrap opacity-0 hover:opacity-100 transition-opacity bg-black px-1 border border-gray-800 pointer-events-none">
        VOICE COMMS
      </div>
    </button>
  );
};

export default VoiceInput;
