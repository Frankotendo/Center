import React, { useState, useEffect, useRef, useCallback } from 'react';
import Terminal from './components/Terminal';
import MissionHub from './components/MissionHub';
import Visualizer from './components/Visualizer';
import TutorBoard from './components/TutorBoard';
import VoiceStatus from './components/VoiceStatus';
import { GameState, Mission, Target, TerminalLine, TargetType, Lecture } from './types';
import { executeCommand, generateSpeech, generateTarget, generateNewMissions, generateLecture } from './services/geminiService';
import { ShieldCheck, Monitor, Activity, Radio, GraduationCap } from 'lucide-react';

// --- INITIAL DATA ---

const MANUAL_MISSIONS: Mission[] = [
  {
    id: 'm1',
    title: 'OP: VERCEL RECON',
    difficulty: 'Beginner',
    description: 'Perform reconnaissance on a suspicious Vercel deployment hosting a phishing site.',
    objectives: ['Identify open ports', 'Find server version', 'Locate hidden directories'],
    targetId: 't1',
    completed: false,
    recommendedTools: ['nmap', 'curl', 'whatweb'],
    briefing: "Operative, uplink established. Target identified as a rogue Vercel node. We need a full port scan to assess vector surface. Execute nmap scan immediately."
  },
  {
    id: 'm2',
    title: 'OP: SUPABASE LEAK',
    difficulty: 'Intermediate',
    description: 'Investigate a misconfigured Supabase instance potentially leaking user data.',
    objectives: ['Detect database port', 'Attempt default credential login', 'Extract table names'],
    targetId: 't2',
    completed: false,
    recommendedTools: ['nmap', 'hydra', 'sqlmap'],
    briefing: "New intelligence. Supabase database node detected with anomalous traffic. Suspected misconfiguration. Probe the PostgreSQL port for access."
  },
  {
    id: 'm3',
    title: 'OP: SILENT AIRWAVES',
    difficulty: 'Intermediate',
    description: 'Intercept and crack the WPA2 handshake of a high-value public WiFi network.',
    objectives: ['Monitor wireless traffic', 'Capture WPA handshake', 'Crack password hash'],
    targetId: 't3',
    completed: false,
    recommendedTools: ['airmon-ng', 'airodump-ng', 'aircrack-ng'],
    briefing: "We are tracking a target utilizing 'Starbucks_Public_WiFi' for sensitive comms. Switch interface to monitor mode and capture the handshake."
  },
  {
    id: 'm4',
    title: 'OP: BROKEN APPLE',
    difficulty: 'Advanced',
    description: 'Exploit a kernel vulnerability in an unpatched iPhone 14 Pro to exfiltrate SMS data.',
    objectives: ['Establish USB tunnel', 'Trigger heap overflow', 'Dump SMS database'],
    targetId: 't4',
    completed: false,
    recommendedTools: ['usbmuxd', 'checkra1n', 'ssh'],
    briefing: "Target device acquired physically: iPhone 14 Pro. iOS version outdated. Vulnerable to checkm8 derivative. Establish tunnel and execute payload."
  },
  {
    id: 'm5',
    title: 'OP: GREEN DEBUG',
    difficulty: 'Beginner',
    description: 'Access a developer device left with ADB debugging enabled over the network.',
    objectives: ['Connect via ADB', 'List installed packages', 'Pull sensitive photos'],
    targetId: 't5',
    completed: false,
    recommendedTools: ['adb', 'nmap'],
    briefing: "Scan indicates a Google Pixel 7 exposing port 5555. Android Debug Bridge is active. Connect and extract file system contents."
  },
  {
    id: 'm6',
    title: 'OP: OPEN BUCKET',
    difficulty: 'Beginner',
    description: 'Enumerate and download files from a misconfigured AWS S3 bucket.',
    objectives: ['List bucket contents', 'Identify sensitive documents', 'Download backup.zip'],
    targetId: 't6',
    completed: false,
    recommendedTools: ['aws-cli', 'curl'],
    briefing: "Corporate intelligence suggests 'mega-corp-backups' bucket is public. Verify permissions and secure the data."
  },
  {
    id: 'm7',
    title: 'OP: GLASS EYE',
    difficulty: 'Intermediate',
    description: 'Hijack the RTSP stream of an insecure IoT security camera.',
    objectives: ['Brute force RTSP credentials', 'Access video feed', 'Freeze frame loop'],
    targetId: 't7',
    completed: false,
    recommendedTools: ['hydra', 'vlc', 'rtsp-simple-server'],
    briefing: "Surveillance camera 'Nest-C2' has weak auth. We need eyes on the interior. Crack the RTSP stream password."
  }
];

// --- PROCEDURAL MISSION GENERATOR ---
const generateCurriculum = (): Mission[] => {
  const missions: Mission[] = [];
  let idCounter = 8;

  const tracks = [
    { 
      code: 'WEB', 
      name: 'WEB_OPS', 
      tools: ['burpsuite', 'sqlmap', 'nikto', 'dirb', 'commix'],
      templates: [
        { title: 'SQL INJECTION', desc: 'Test for SQLi vulnerabilities in the login portal.' },
        { title: 'XSS AUDIT', desc: 'Identify reflected XSS in search parameters.' },
        { title: 'CSRF BYPASS', desc: 'Attempt to bypass CSRF tokens on profile update.' },
        { title: 'IDOR CHECK', desc: 'Test Insecure Direct Object References on user API.' },
        { title: 'JWT CRACK', desc: 'Brute force weak secrets in JSON Web Tokens.' }
      ]
    },
    { 
      code: 'NET', 
      name: 'NET_SEC', 
      tools: ['nmap', 'masscan', 'metasploit', 'wireshark', 'netcat'],
      templates: [
        { title: 'PORT SCAN', desc: 'Perform aggressive port scan on gateway.' },
        { title: 'SMB ETERNAL', desc: 'Check for MS17-010 EternalBlue vulnerability.' },
        { title: 'FTP ANON', desc: 'Test Anonymous Login capabilities on FTP server.' },
        { title: 'SSH BRUTE', desc: 'Audit SSH credential strength via Hydra.' },
        { title: 'DNS ZONE', desc: 'Attempt DNS Zone Transfer (AXFR) on nameserver.' }
      ]
    },
    { 
      code: 'WIFI', 
      name: 'WIFI_SIGINT', 
      tools: ['aircrack-ng', 'wifite', 'kismet', 'reaver', 'hashcat'],
      templates: [
        { title: 'WPS PIN', desc: 'Attempt Pixie Dust attack on WPS enabled AP.' },
        { title: 'EVIL TWIN', desc: 'Simulate Evil Twin AP to capture credentials.' },
        { title: 'DEAUTH FLOOD', desc: 'Test network resilience against deauth packets.' },
        { title: 'HIDDEN SSID', desc: 'Decloak hidden SSID via probe request sniffing.' },
        { title: 'WPA2 DICT', desc: 'Capture handshake and run dictionary attack.' }
      ]
    },
    { 
      code: 'MOB', 
      name: 'MOBILE_INTEL', 
      tools: ['adb', 'frida', 'objection', 'apktool', 'mobisf'],
      templates: [
        { title: 'APK REVERSE', desc: 'Decompile APK and search for hardcoded API keys.' },
        { title: 'INTENT SNIFF', desc: 'Monitor insecure Android Intents broadcasting data.' },
        { title: 'IOS JAILBREAK', desc: 'Detect jailbreak artifacts on target iPhone.' },
        { title: 'KEYCHAIN DUMP', desc: 'Attempt to dump iOS Keychain via SSH.' },
        { title: 'ADB SHELL', desc: 'Gain shell access via exposed ADB port.' }
      ]
    },
    { 
      code: 'CLOUD', 
      name: 'CLOUD_WARFARE', 
      tools: ['aws-cli', 'pacu', 'scoutsuite', 'cloudsploit', 'az-cli'],
      templates: [
        { title: 'IAM PRIVESC', desc: 'Audit IAM roles for privilege escalation paths.' },
        { title: 'S3 EXPOSURE', desc: 'Scan for public read/write ACLs on buckets.' },
        { title: 'LAMBDA INJECT', desc: 'Test Serverless function for code injection.' },
        { title: 'METADATA SSRF', desc: 'Hit instance metadata service (IMDSv1) via SSRF.' },
        { title: 'K8S ESCAPE', desc: 'Attempt container breakout to host node.' }
      ]
    },
    { 
      code: 'IOT', 
      name: 'IOT_CONTROL', 
      tools: ['binwalk', 'shodan', 'mqtt-spy', 'rplay', 'hackrf'],
      templates: [
        { title: 'MQTT SNIFF', desc: 'Intercept unencrypted MQTT messages from sensors.' },
        { title: 'FIRMWARE EXT', desc: 'Extract filesystem from binary firmware image.' },
        { title: 'BLE REPLAY', desc: 'Capture and replay Bluetooth Low Energy packets.' },
        { title: 'RTSP HIJACK', desc: 'Brute force RTSP stream credentials.' },
        { title: 'ZIGBEE MAP', desc: 'Map Zigbee mesh network topology.' }
      ]
    }
  ];

  const difficulties = ['Beginner', 'Intermediate', 'Advanced', 'Expert'];

  // Generate ~15 missions per track to reach ~90 + 7 manual = ~100
  tracks.forEach(track => {
    for (let i = 1; i <= 16; i++) {
        const template = track.templates[i % track.templates.length];
        const difficulty = difficulties[Math.floor(Math.random() * difficulties.length)];
        const targetNum = Math.floor(Math.random() * 999) + 100;
        
        missions.push({
            id: `m${idCounter}`,
            title: `OP: ${track.code}-${targetNum} // ${template.title}`,
            difficulty: difficulty as any,
            description: `${template.desc} Target designated as T-${targetNum}.`,
            objectives: ['Establish Uplink', template.title, 'Exfiltrate Data', 'Cover Tracks'],
            targetId: `t${idCounter}`,
            completed: false,
            recommendedTools: [track.tools[i % track.tools.length], track.tools[(i+1) % track.tools.length]],
            briefing: `Operative, new contract available. Sector: ${track.name}. ${template.desc} Proceed with caution.`
        });
        idCounter++;
    }
  });

  return missions;
};

const INITIAL_MISSIONS = [...MANUAL_MISSIONS, ...generateCurriculum()];


const INITIAL_TARGETS: Record<string, Target> = {
  't1': {
    id: 't1',
    name: 'phish-login.vercel.app',
    type: TargetType.WEBSITE,
    ip: '76.76.21.21',
    os: 'Vercel/Serverless',
    vulnerabilities: [],
    ports: [],
    status: 'online',
    description: 'A React frontend hosted on Vercel.'
  },
  't2': {
    id: 't2',
    name: 'db.supabase.co',
    type: TargetType.DATABASE,
    ip: '54.23.11.102',
    os: 'Linux (Ubuntu)',
    vulnerabilities: [],
    ports: [],
    status: 'online',
    description: 'PostgreSQL Database hosted on Supabase.'
  },
  't3': {
    id: 't3',
    name: 'Starbucks_Public_WiFi',
    type: TargetType.WIFI,
    ip: '192.168.1.1',
    os: 'Cisco IOS (WAP)',
    vulnerabilities: [],
    ports: [],
    status: 'online',
    description: 'Public WPA2-PSK Network.'
  },
  't4': {
    id: 't4',
    name: 'iPhone 14 Pro',
    type: TargetType.IPHONE,
    ip: '192.168.1.105',
    os: 'iOS 16.1',
    vulnerabilities: [],
    ports: [],
    status: 'online',
    description: 'Target personal device. Unpatched.'
  },
  't5': {
    id: 't5',
    name: 'Pixel 7 Dev',
    type: TargetType.ANDROID,
    ip: '192.168.1.108',
    os: 'Android 13',
    vulnerabilities: [],
    ports: [],
    status: 'online',
    description: 'Developer device with ADB exposed.'
  },
  't6': {
    id: 't6',
    name: 's3://mega-corp-backups',
    type: TargetType.WEBSITE,
    ip: '52.216.0.0',
    os: 'AWS S3',
    vulnerabilities: [],
    ports: [],
    status: 'online',
    description: 'Publicly accessible S3 storage bucket.'
  },
  't7': {
    id: 't7',
    name: 'Nest Cam Outdoor',
    type: TargetType.IOT,
    ip: '192.168.1.50',
    os: 'Embedded Linux',
    vulnerabilities: [],
    ports: [],
    status: 'online',
    description: 'IP Camera with RTSP interface.'
  }
};

const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

type PanelId = 'none' | 'mission' | 'visualizer' | 'terminal' | 'tutor';
type RightPanelMode = 'tactical' | 'classroom';

const App: React.FC = () => {
  const [gameState, setGameState] = useState<GameState>({
    currentMissionId: null,
    missions: INITIAL_MISSIONS,
    targets: INITIAL_TARGETS,
    terminalHistory: [{ type: 'system', content: 'CyberSim AI OS v2.4 Initialized...\nUplink Established.\nType "help" for commands.\nType "learn <topic>" to start a class.', timestamp: Date.now() }],
    isProcessing: false,
    isPlayingAudio: false,
    activeLecture: null
  });

  const [maximizedPanel, setMaximizedPanel] = useState<PanelId>('none');
  const [rightPanelMode, setRightPanelMode] = useState<RightPanelMode>('tactical');

  const toggleMaximize = (panel: PanelId) => {
    setMaximizedPanel(prev => prev === panel ? 'none' : panel);
  };

  const audioContextRef = useRef<AudioContext | null>(null);

  // --- AUDIO HANDLING ---

  const pcmToAudioBuffer = (
    data: ArrayBuffer,
    ctx: AudioContext,
    sampleRate: number = 24000,
    numChannels: number = 1
  ): AudioBuffer => {
    const dataInt16 = new Int16Array(data);
    const frameCount = dataInt16.length / numChannels;
    const buffer = ctx.createBuffer(numChannels, frameCount, sampleRate);

    for (let channel = 0; channel < numChannels; channel++) {
      const channelData = buffer.getChannelData(channel);
      for (let i = 0; i < frameCount; i++) {
        channelData[i] = dataInt16[i * numChannels + channel] / 32768.0;
      }
    }
    return buffer;
  };

  const playAudio = useCallback(async (buffer: ArrayBuffer) => {
    if (!audioContextRef.current) {
      audioContextRef.current = new (window.AudioContext || (window as any).webkitAudioContext)();
    }
    const ctx = audioContextRef.current;
    
    // Resume context if suspended (browser autoplay policy)
    if (ctx.state === 'suspended') {
      await ctx.resume();
    }
    
    try {
      const audioBuffer = pcmToAudioBuffer(buffer, ctx);
      const source = ctx.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(ctx.destination);
      
      setGameState(prev => ({ ...prev, isPlayingAudio: true }));
      
      source.onended = () => {
        setGameState(prev => ({ ...prev, isPlayingAudio: false }));
      };
      
      source.start(0);
    } catch (e) {
      console.error("Audio Playback Failed", e);
      setGameState(prev => ({ ...prev, isPlayingAudio: false }));
    }
  }, []);

  const speak = useCallback(async (text: string) => {
      if (!process.env.API_KEY) {
          console.warn("API_KEY missing. Audio disabled.");
          return;
      }
      const audioData = await generateSpeech(text);
      if (audioData) {
        playAudio(audioData);
      }
  }, [playAudio]);


  // --- GAME LOGIC ---

  const handleSelectMission = async (id: string) => {
    const mission = gameState.missions.find(m => m.id === id);
    if (!mission) return;

    // Check if target exists
    let target = gameState.targets[mission.targetId];
    if (!target) {
        setGameState(prev => ({...prev, isProcessing: true}));
        // Identify target type based on mission title/desc for better generation hint
        const typeHint = mission.title.includes('WIFI') ? 'WiFi Network' : 
                         mission.title.includes('MOB') ? 'Mobile Device' :
                         mission.title.includes('CLOUD') ? 'Cloud Infrastructure' :
                         mission.title.includes('IOT') ? 'IoT Device' : 'Server';

        target = await generateTarget(mission.targetId, `${mission.description} Type: ${typeHint}`);
        setGameState(prev => ({
            ...prev,
            isProcessing: false,
            targets: { ...prev.targets, [target.id]: target }
        }));
    }

    setGameState(prev => ({
      ...prev,
      currentMissionId: id,
      terminalHistory: [
        ...prev.terminalHistory,
        { type: 'system', content: `\n// MISSION LOADING: ${mission.title}...\n// BRIEFING: ${mission.briefing}`, timestamp: Date.now() }
      ]
    }));
    
    setRightPanelMode('tactical'); // Switch to ops view on mission select
    speak(mission.briefing);
  };

  // --- LECTURE LOGIC ---

  const handleStartLecture = async (topic: string) => {
      setRightPanelMode('classroom');
      setGameState(prev => ({
            ...prev,
            isProcessing: true,
            terminalHistory: [...prev.terminalHistory, { type: 'system', content: `\n// INITIATING ACADEMIC PROTOCOL: ${topic.toUpperCase()}...`, timestamp: Date.now() }]
      }));

      const lecture = await generateLecture(topic);
        
      setGameState(prev => ({
            ...prev,
            isProcessing: false,
            activeLecture: lecture,
            terminalHistory: [
                ...prev.terminalHistory,
                { type: 'system', content: `// LECTURE READY: ${topic.toUpperCase()}`, timestamp: Date.now() }
            ]
      }));
        
      if (lecture.steps.length > 0) {
            speak(lecture.steps[0].voiceScript);
      }
  };

  const handleNextLectureStep = () => {
      if (!gameState.activeLecture) return;

      const nextIndex = gameState.activeLecture.currentStepIndex + 1;
      
      if (nextIndex < gameState.activeLecture.steps.length) {
          const nextStep = gameState.activeLecture.steps[nextIndex];
          setGameState(prev => ({
              ...prev,
              activeLecture: {
                  ...prev.activeLecture!,
                  currentStepIndex: nextIndex
              }
          }));
          speak(nextStep.voiceScript);
      } else {
          // Finish class
           setGameState(prev => ({
              ...prev,
              activeLecture: null,
              terminalHistory: [
                  ...prev.terminalHistory,
                  { type: 'system', content: `\n// CLASS DISMISSED: ${prev.activeLecture!.topic}. RESUMING OPS.`, timestamp: Date.now() }
              ]
          }));
          speak("Class dismissed. You may return to operations or practice what you've learned.");
      }
  };


  const handleCommand = async (cmd: string) => {
    if (cmd === 'clear') {
      setGameState(prev => ({ ...prev, terminalHistory: [] }));
      return;
    }
    if (cmd === 'help') {
      setGameState(prev => ({ 
        ...prev, 
        terminalHistory: [...prev.terminalHistory, { type: 'system', content: 'AVAILABLE TOOLS:\n- nmap [target]\n- curl [url]\n- sqlmap -u [url]\n- msfconsole\n- hydra -l [user] -P [pass] [target] ssh\n- learn [topic] (Starts AI Tutor)\n- generate missions (Create new AI Ops)', timestamp: Date.now() }] 
      }));
      return;
    }

    // --- HANDLE GENERATE MISSIONS ---
    if (cmd === 'generate missions' || cmd === 'gen ops') {
        setGameState(prev => ({
            ...prev,
            isProcessing: true,
            terminalHistory: [...prev.terminalHistory, { type: 'input', content: cmd, timestamp: Date.now() }]
        }));

        speak("Acknowledged. Requesting new mission profiles from High Command.");

        // Calculate difficulty based on progress
        const completedCount = gameState.missions.filter(m => m.completed).length;
        
        try {
            const newMissions = await generateNewMissions(completedCount);
            
            // Fix potential ID collisions or ensure they are unique enough
            const processedMissions = newMissions.map((m, idx) => ({
                ...m,
                id: `ai-gen-${Date.now()}-${idx}`,
                targetId: `ai-target-${Date.now()}-${idx}`
            }));

            setGameState(prev => ({
                ...prev,
                isProcessing: false,
                missions: [...prev.missions, ...processedMissions],
                terminalHistory: [
                    ...prev.terminalHistory,
                    { type: 'system', content: `\n// UPLINK SUCCESSFUL.\n// ${processedMissions.length} NEW OPERATIONS GENERATED.\n// CHECK MISSION HUB.`, timestamp: Date.now() }
                ]
            }));
        } catch (error) {
             setGameState(prev => ({
                ...prev,
                isProcessing: false,
                terminalHistory: [
                    ...prev.terminalHistory,
                    { type: 'error', content: `ERROR: UPLINK FAILED. COULD NOT GENERATE MISSIONS.`, timestamp: Date.now() }
                ]
            }));
        }
        return;
    }

    // --- HANDLE LEARNING COMMANDS ---
    if (cmd.startsWith('learn ') || cmd.startsWith('teach ')) {
        const topic = cmd.replace(/^(learn|teach)\s+/, '');
        handleStartLecture(topic);
        return;
    }

    if (!gameState.currentMissionId) {
      setGameState(prev => ({ 
        ...prev, 
        terminalHistory: [
            ...prev.terminalHistory, 
            { type: 'input', content: cmd, timestamp: Date.now() },
            { type: 'error', content: 'ERROR: NO TARGET DESIGNATED. SELECT MISSION.', timestamp: Date.now() }
        ] 
      }));
      return;
    }

    const mission = gameState.missions.find(m => m.id === gameState.currentMissionId)!;
    const target = gameState.targets[mission.targetId];

    setGameState(prev => ({ 
        ...prev, 
        isProcessing: true,
        terminalHistory: [...prev.terminalHistory, { type: 'input', content: cmd, timestamp: Date.now() }] 
    }));

    // Artificial Latency
    const isScan = cmd.includes('nmap') || cmd.includes('scan');
    const isAttack = cmd.includes('exploit') || cmd.includes('hydra');
    await wait(isScan ? 2500 : isAttack ? 3000 : 1000);

    const historySummary = gameState.terminalHistory.slice(-5).map(l => l.content).join('\n');
    const result = await executeCommand(cmd, mission, target, historySummary);

    // Prepare updates
    let newMissions = [...gameState.missions];
    let newTargets = { ...gameState.targets };
    let didCompleteMission = false;

    // Apply Target Updates
    if (result.targetUpdate) {
        const currentTarget = newTargets[mission.targetId];
        newTargets[mission.targetId] = {
            ...currentTarget,
            ...result.targetUpdate,
            ports: Array.from(new Set([...currentTarget.ports, ...(result.targetUpdate.ports || [])])),
            vulnerabilities: Array.from(new Set([...currentTarget.vulnerabilities, ...(result.targetUpdate.vulnerabilities || [])]))
        };
    }

    // Apply Mission Updates
    if (result.missionUpdate?.status === 'completed') {
         const mIndex = newMissions.findIndex(m => m.id === mission.id);
         if (mIndex > -1 && !newMissions[mIndex].completed) {
             newMissions[mIndex].completed = true;
             didCompleteMission = true;
         }
    }

    setGameState(prev => ({
        ...prev,
        isProcessing: false,
        missions: newMissions,
        targets: newTargets,
        terminalHistory: [
            ...prev.terminalHistory,
            { type: 'output', content: result.terminalOutput, timestamp: Date.now() },
            { type: 'system', content: `[KORE]: ${result.instructorCommentary}`, timestamp: Date.now() }
        ]
    }));

    speak(result.instructorCommentary);

    // Handle Dynamic Mission Generation (After update)
    if (didCompleteMission) {
        const completedCount = newMissions.filter(m => m.completed).length;
        generateNewMissions(completedCount).then(generated => {
            if (generated.length > 0) {
                 setGameState(curr => ({
                     ...curr,
                     missions: [...curr.missions, ...generated],
                     terminalHistory: [
                         ...curr.terminalHistory,
                         { type: 'system', content: `\n// HQ UPLINK: ${generated.length} NEW MISSIONS RECEIVED.\n// CHECK OPERATION LOG.`, timestamp: Date.now() }
                     ]
                 }));
                 speak("Objective complete. New tactical assignments have been uploaded to your operational hub.");
            }
        });
    }
  };

  return (
    <div className="relative w-screen h-screen bg-[#020202] text-gray-200 overflow-hidden font-rajdhani crt">
      {/* App Container */}
      <div className="relative z-10 flex flex-col h-full p-2 md:p-4 gap-4">
        
        {/* Header */}
        <header className="flex items-center justify-between bg-[#0a0a0a] border border-gray-800 p-3 rounded shrink-0 z-50">
            <div className="flex items-center gap-4">
                <div className="w-10 h-10 bg-purple-900/20 border border-purple-500/50 rounded flex items-center justify-center">
                    <Monitor className="text-purple-400" size={20} />
                </div>
                <div>
                    <h1 className="text-2xl font-bold tracking-widest text-white uppercase font-tech">CyberSim <span className="text-purple-500">PRO</span></h1>
                    <div className="flex items-center gap-2 text-[10px] text-gray-500 font-mono">
                        <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                        SYSTEM ONLINE v2.4
                    </div>
                </div>
            </div>
            
            {/* Mode Switcher */}
            <div className="hidden md:flex bg-gray-900 rounded p-1 border border-gray-800">
                <button 
                    onClick={() => setRightPanelMode('tactical')}
                    className={`flex items-center gap-2 px-3 py-1 text-xs rounded transition-colors ${rightPanelMode === 'tactical' ? 'bg-blue-900/50 text-blue-400' : 'text-gray-500 hover:text-gray-300'}`}
                >
                    <Activity size={14} /> OPS VIEW
                </button>
                <button 
                     onClick={() => setRightPanelMode('classroom')}
                    className={`flex items-center gap-2 px-3 py-1 text-xs rounded transition-colors ${rightPanelMode === 'classroom' ? 'bg-emerald-900/50 text-emerald-400' : 'text-gray-500 hover:text-gray-300'}`}
                >
                    <Radio size={14} /> CLASSROOM
                </button>
            </div>

            {/* AI Tutor Trigger (Mobile/Extra) */}
            <button 
                onClick={() => setRightPanelMode('classroom')}
                className="md:hidden p-2 text-emerald-400 bg-emerald-900/20 rounded border border-emerald-800"
            >
                <GraduationCap size={20} />
            </button>
            
            <div className="flex items-center gap-6">
                <div className="hidden md:block text-right">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wider">Operator</div>
                    <div className="text-sm text-blue-400 font-mono">UNIT_734</div>
                </div>
                <VoiceStatus isPlaying={gameState.isPlayingAudio} />
            </div>
        </header>

        {/* Main Content */}
        <main className="flex-1 grid grid-cols-1 md:grid-cols-12 gap-4 min-h-0 relative z-30">
            {/* Left Panel (Missions) */}
            <div className={`
                ${maximizedPanel === 'mission' ? 'md:col-span-12 z-40 absolute inset-0 bg-[#020202]' : 'md:col-span-3'} 
                ${maximizedPanel !== 'none' && maximizedPanel !== 'mission' ? 'hidden' : 'flex'}
                flex-col h-full min-h-0 transition-all duration-300
            `}>
                <MissionHub 
                    missions={gameState.missions} 
                    currentMissionId={gameState.currentMissionId}
                    onSelectMission={handleSelectMission}
                    targets={gameState.targets}
                    isMaximized={maximizedPanel === 'mission'}
                    onToggleMaximize={() => toggleMaximize('mission')}
                />
            </div>

            {/* Right Panel Container */}
            <div className={`
                ${maximizedPanel === 'visualizer' || maximizedPanel === 'terminal' || maximizedPanel === 'tutor' ? 'md:col-span-12 z-40 absolute inset-0 bg-[#020202]' : 'md:col-span-9'}
                ${maximizedPanel === 'mission' ? 'hidden' : 'flex'}
                flex-col gap-4 h-full min-h-0 transition-all duration-300
            `}>
                
                {/* Visualizer / Tutor Area */}
                <div className={`
                    ${maximizedPanel === 'visualizer' || maximizedPanel === 'tutor' ? 'h-full' : 'h-[40%]'}
                    ${maximizedPanel === 'terminal' ? 'hidden' : 'block'}
                    transition-all duration-300
                `}>
                    {rightPanelMode === 'tactical' ? (
                        <Visualizer 
                            target={gameState.currentMissionId ? gameState.targets[gameState.missions.find(m => m.id === gameState.currentMissionId)!.targetId] : null} 
                            isMaximized={maximizedPanel === 'visualizer'}
                            onToggleMaximize={() => toggleMaximize('visualizer')}
                        />
                    ) : (
                        <TutorBoard 
                            lecture={gameState.activeLecture}
                            onNextStep={handleNextLectureStep}
                            onStartLecture={handleStartLecture}
                            isMaximized={maximizedPanel === 'tutor'}
                            onToggleMaximize={() => toggleMaximize('tutor')}
                            isLoading={gameState.isProcessing}
                            isPlayingAudio={gameState.isPlayingAudio}
                        />
                    )}
                </div>
                
                {/* Terminal */}
                <div className={`
                    ${maximizedPanel === 'terminal' ? 'h-full' : 'flex-1'}
                    ${maximizedPanel === 'visualizer' || maximizedPanel === 'tutor' ? 'hidden' : 'block'}
                    min-h-0 transition-all duration-300
                `}>
                    <Terminal 
                        history={gameState.terminalHistory} 
                        onCommand={handleCommand} 
                        isProcessing={gameState.isProcessing}
                        isMaximized={maximizedPanel === 'terminal'}
                        onToggleMaximize={() => toggleMaximize('terminal')}
                    />
                </div>
            </div>
        </main>

      </div>
    </div>
  );
};

export default App;