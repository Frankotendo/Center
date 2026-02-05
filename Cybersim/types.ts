
export interface TerminalLine {
  type: 'input' | 'output' | 'system' | 'error';
  content: string;
  timestamp: number;
}

export enum TargetType {
  WEBSITE = 'Website',
  DATABASE = 'Database',
  IPHONE = 'iPhone',
  ANDROID = 'Android',
  IOT = 'IoT Device',
  SERVER = 'Linux Server',
  CLOUD_FUNCTION = 'Cloud Function',
  WIFI = 'WiFi Network',
  BLOCKCHAIN = 'Smart Contract'
}

export interface Target {
  id: string;
  name: string;
  type: TargetType;
  ip: string;
  os: string;
  vulnerabilities: string[]; // Discovered vulnerabilities
  ports: number[]; // Discovered ports
  status: 'online' | 'compromised' | 'offline';
  description: string;
}

export interface Mission {
  id: string;
  title: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced' | 'Expert';
  description: string;
  objectives: string[];
  targetId: string;
  completed: boolean;
  recommendedTools: string[];
  briefing: string; // Spoken by AI
}

export interface LectureStep {
  voiceScript: string; // What the teacher says
  boardNotes: string;  // What appears on the whiteboard
}

export interface Lecture {
  topic: string;
  steps: LectureStep[];
  currentStepIndex: number;
}

export interface GameState {
  currentMissionId: string | null;
  missions: Mission[];
  targets: Record<string, Target>;
  terminalHistory: TerminalLine[];
  isProcessing: boolean;
  isPlayingAudio: boolean;
  activeLecture: Lecture | null; // New field for classroom state
}

export interface SimulationResponse {
  terminalOutput: string;
  instructorCommentary: string; // To be spoken
  missionUpdate?: {
    status: 'ongoing' | 'completed' | 'failed';
    progressLog?: string;
  };
  targetUpdate?: Partial<Target>;
  systemAction?: 'none' | 'generate_missions';
  suggestedMissionTopic?: string;
}
