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
    title: 'OP: POWER GRID ZERO',
    difficulty: 'Expert',
    description: 'Infiltrate a SCADA PLS controlling a regional substation. DANGEROUS.',
    objectives: ['Scan Modbus registry', 'Inject false coil data', 'Disable failsafes'],
    targetId: 't8',
    completed: false,
    recommendedTools: ['modbus-cli', 'metasploit', 'scadascan'],
    briefing: "High priority. Hostile state actor infrastructure. Target is a Siemens S7-1200 PLC. Access via Modbus TCP. Shut it down."
  },
  {
    id: 'm6',
    title: 'OP: CRYPTO HEIST',
    difficulty: 'Expert',
    description: 'Recover stolen funds from a compromised hardware wallet seed phrase.',
    objectives: ['Brute force BIP39 seed', 'Access wallet', 'Transfer assets to secure vault'],
    targetId: 't9',
    completed: false,
    recommendedTools: ['hashcat', 'john', 'btc-recover'],
    briefing: "We have intercepted a partial mnemonic seed phrase from a ransomware gang. Use distributed cracking to recover the private key."
  },
  {
    id: 'm7',
    title: 'OP: DARK MARKET',
    difficulty: 'Advanced',
    description: 'De-anonymize a hidden Tor service hosting illegal contraband.',
    objectives: ['Identify backend IP', 'Bypass Tor circuit', 'Dump admin database'],
    targetId: 't10',
    completed: false,
    recommendedTools: ['nmap', 'nikto', 'onion-scan'],
    briefing: "Target is a .onion hidden service. Intelligence indicates a misconfigured Apache header leaking the real IP. Find it."
  }
];

// --- PROCEDURAL MISSION GENERATOR ---
const generateCurriculum = (): Mission[] => {
  const missions: Mission[] = [];
  let idCounter = 100; // Start higher to avoid collision

  const tracks = [
    { 
      code: 'WEB', 
      name: 'ADVANCED_WEB', 
      tools: ['burpsuite', 'sqlmap', 'commix', 'xsstrike', 'wpscan', 'feroxbuster', 'dalfox'],
      templates: [
        { title: 'SQL INJECTION BLIND', desc: 'Exploit Time-Based Blind SQLi to extract admin hash byte-by-byte.' },
        { title: 'RCE DESERIALIZATION', desc: 'Exploit unsafe PHP object deserialization to gain remote shell.' },
        { title: 'XXE EXFILTRATION', desc: 'Weaponize XML External Entity to read /etc/passwd.' },
        { title: 'SSRF CLOUD', desc: 'Abuse SSRF to access AWS metadata service credentials.' },
        { title: 'GRAPHQL INTROSPECTION', desc: 'Enumerate entire backend schema via introspection query.' },
        { title: 'LFI TO SHELL', desc: 'Elevate Local File Inclusion to RCE via Apache log poisoning.' },
        { title: 'OAUTH TAKEOVER', desc: 'Hijack user account via weak OAuth redirect_uri validation.' },
        { title: 'WEB SOCKET HIJACK', desc: 'Cross-Site WebSocket Hijacking (CSWSH) to steal live session.' },
        { title: 'HTTP REQUEST SMUGGLING', desc: 'Desync front-end and back-end servers to bypass firewall.' },
        { title: 'TEMPLATE INJECTION', desc: 'Server-Side Template Injection (SSTI) in Python Flask app.' }
      ]
    },
    { 
      code: 'NET', 
      name: 'NETWORK_WARFARE', 
      tools: ['nmap', 'metasploit', 'responder', 'crackmapexec', 'impacket', 'bloodhound'],
      templates: [
        { title: 'ETERNALBLUE MS17-010', desc: 'Deploy EternalBlue exploit against unpatched SMB server.' },
        { title: 'KERBEROASTING', desc: 'Request TGS tickets to crack service account passwords offline.' },
        { title: 'LLMNR POISONING', desc: 'Spoof name resolution to capture NTLMv2 hashes.' },
        { title: 'DOMAIN ADMIN PATH', desc: 'Map attack path to Domain Admin using BloodHound analysis.' },
        { title: 'ARP SPOOF MITM', desc: 'Man-in-the-Middle attack to intercept cleartext FTP creds.' },
        { title: 'DNS TUNNELING', desc: 'Exfiltrate confidential data over DNS queries (C2).' },
        { title: 'PASS-THE-HASH', desc: 'Lateral movement using captured NTLM hash without cracking.' },
        { title: 'VLAN HOPPING', desc: 'Double-tag frames to access restricted management VLAN.' },
        { title: 'RDP BLUEKEEP', desc: 'Exploit BlueKeep RCE vulnerability in Remote Desktop.' },
        { title: 'SNMP ENUMERATION', desc: 'Extract full network map via public SNMP community string.' }
      ]
    },
    { 
      code: 'RED', 
      name: 'RED_TEAM_OPS', 
      tools: ['cobalt-strike', 'empire', 'msfvenom', 'shellter', 'veil', 'evilginx2'],
      templates: [
        { title: 'PAYLOAD OBFUSCATION', desc: 'Generate FUD (Fully Undetectable) payload to bypass AV.' },
        { title: 'PROCESS MIGRATION', desc: 'Inject shellcode into legitimate explorer.exe process.' },
        { title: 'PERSISTENCE REGISTRY', desc: 'Establish persistence via HKCU Run keys.' },
        { title: 'DLL SIDE-LOADING', desc: 'Hijack DLL search order to execute malicious code.' },
        { title: 'PHISHING CAMPAIGN', desc: 'Clone corporate login page for credential harvesting.' },
        { title: 'MACRO WEAPONIZATION', desc: 'Embed VBA reverse shell in Excel document.' },
        { title: 'AMSI BYPASS', desc: 'Disable Antimalware Scan Interface via PowerShell reflection.' }
      ]
    },
    { 
      code: 'WIFI', 
      name: 'WIRELESS_SIGINT', 
      tools: ['aircrack-ng', 'wifite', 'bettercap', 'kismet', 'hostapd-mana', 'eaphammer'],
      templates: [
        { title: 'EVIL TWIN PORTAL', desc: 'Deploy rogue AP with captive portal to harvest creds.' },
        { title: 'PMKID ATTACK', desc: 'Capture PMKID from AP (clientless) and crack hash.' },
        { title: 'WPS PIXIE DUST', desc: 'Offline brute force attack against WPS implementation.' },
        { title: 'DEAUTH JAMMING', desc: 'Targeted deauthentication attack to force reconnection.' },
        { title: 'BLE SNIFFING', desc: 'Intercept Bluetooth Low Energy smart lock keys.' },
        { title: 'MOUSEJACKING', desc: 'Inject keystrokes into vulnerable wireless dongle.' }
      ]
    },
    { 
      code: 'MOB', 
      name: 'MOBILE_INTEL', 
      tools: ['adb', 'frida', 'objection', 'drozer', 'mobisf', 'apktool'],
      templates: [
        { title: 'INTENT SNIFFING', desc: 'Intercept unsecure Android Intents leaking token.' },
        { title: 'DEEPLINK HIJACK', desc: 'Exploit custom URL scheme to trigger unauthorized actions.' },
        { title: 'SSL PINNING BYPASS', desc: 'Hook runtime via Frida to disable certificate validation.' },
        { title: 'KEYCHAIN DUMP', desc: 'Decrypt iOS Keychain entries via jailbreak access.' },
        { title: 'ADB BACKDOOR', desc: 'Install persistent backdoor via exposed ADB port.' },
        { title: 'OVERLAY ATTACK', desc: 'Draw fake login window over legitimate banking app.' }
      ]
    },
    { 
      code: 'SCADA', 
      name: 'INDUSTRIAL_ICS', 
      tools: ['modbus-cli', 's7scan', 'plcscan', 'snap7', 'shodan'],
      templates: [
        { title: 'MODBUS COIL WRITE', desc: 'Send unauthorized coil write command to PLC.' },
        { title: 'HMI DOS ATTACK', desc: 'Disrupt Human Machine Interface via packet flooding.' },
        { title: 'PLC LOGIC BOMB', desc: 'Upload modified ladder logic to Siemens controller.' },
        { title: 'S7 COMM HIJACK', desc: 'Intercept S7comm protocol data to alter sensor readings.' },
        { title: 'POWER GRID SIM', desc: 'Simulate breaker trip command on substation RTU.' }
      ]
    },
    { 
      code: 'CLOUD', 
      name: 'CLOUD_WARFARE', 
      tools: ['aws-cli', 'pacu', 'scoutsuite', 'kube-hunter', 'cloudsploit'],
      templates: [
        { title: 'IAM PRIVILEGE ESC', desc: 'Exploit "PassRole" permission to create admin user.' },
        { title: 'S3 BUCKET LEAK', desc: 'Scan and download sensitive PII from public bucket.' },
        { title: 'LAMBDA INJECTION', desc: 'Inject code into Serverless function environment.' },
        { title: 'K8S POD ESCAPE', desc: 'Break out of container to access host node filesystem.' },
        { title: 'EC2 USER DATA', desc: 'Extract secrets from EC2 User Data startup scripts.' }
      ]
    },
    { 
      code: 'CRYPTO', 
      name: 'CRYPTANALYSIS', 
      tools: ['hashcat', 'john', 'hydra', 'btc-recover', 'mythril'],
      templates: [
        { title: 'WALLET CRACKING', desc: 'Brute force encrypted cryptocurrency wallet.dat.' },
        { title: 'SMART CONTRACT BUG', desc: 'Exploit reentrancy vulnerability in Solidity contract.' },
        { title: 'JWT KEY CRACK', desc: 'Brute force weak HMAC secret in JSON Web Token.' },
        { title: 'HASH COLLISION', desc: 'Generate hash collision for MD5 signature bypass.' }
      ]
    }
  ];

  const difficulties = ['Beginner', 'Intermediate', 'Advanced', 'Expert', 'Black Ops'];

  // Generate missions to reach ~100 total (approx 12 per track)
  tracks.forEach(track => {
    for (let i = 0; i < 12; i++) {
        const template = track.templates[i % track.templates.length];
        const difficulty = difficulties[Math.min(Math.floor(i / 3), 4)];
        const targetNum = Math.floor(Math.random() * 8999) + 1000;
        
        missions.push({
            id: `m${idCounter}`,
            title: `OP: ${track.code}-${targetNum} // ${template.title}`,
            difficulty: difficulty as any,
            description: `${template.desc} Target designated as T-${targetNum}.`,
            objectives: ['Establish Uplink', 'Reconnaissance', template.title, 'Exfiltrate/Destroy', 'Cover Tracks'],
            targetId: `t${idCounter}`,
            completed: false,
            recommendedTools: [track.tools[i % track.tools.length], track.tools[(i+1) % track.tools.length]],
            briefing: `Operative, new contract available. Sector: ${track.name}. Mission: ${template.desc}. Failure is not an option.`
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
  't8': {
    id: 't8',
    name: 'SIEMENS S7-1200',
    type: TargetType.SCADA,
    ip: '10.20.100.5',
    os: 'Siemens Firmware v4.0',
    vulnerabilities: [],
    ports: [],
    status: 'online',
    description: 'Industrial PLC controlling substation breakers.'
  },
  't9': {
    id: 't9',
    name: 'Encrypted Ledger Nano',
    type: TargetType.BLOCKCHAIN,
    ip: 'N/A',
    os: 'Secure Element',
    vulnerabilities: [],
    ports: [],
    status: 'online',
    description: 'Hardware wallet with weak seed phrase.'
  },
  't10': {
    id: 't10',
    name: 'silkroad4.onion',
    type: TargetType.SERVER,
    ip: '10.200.5.1',
    os: 'Debian 10 (Tor Node)',
    vulnerabilities: [],
    ports: [],
    status: 'online',
    description: 'Hidden Service hosting contraband market.'
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
    terminalHistory: [{ type: 'system', content: 'CyberSim AI OS v3.0 Initialized...\nGLOBAL THREAT MAP LOADED.\nDARKNET UPLINK: ACTIVE.\nType "help" for commands.\nType "missions" to list operations.', timestamp: Date.now() }],
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
        let typeHint = 'Server';
        if (mission.title.includes('WIFI')) typeHint = 'WiFi Network';
        else if (mission.title.includes('MOB') || mission.title.includes('IPHONE')) typeHint = 'Mobile Device';
        else if (mission.title.includes('CLOUD') || mission.title.includes('AWS')) typeHint = 'Cloud Infrastructure';
        else if (mission.title.includes('IOT')) typeHint = 'IoT Device';
        else if (mission.title.includes('SCADA') || mission.title.includes('PLC')) typeHint = 'Industrial Control System';
        else if (mission.title.includes('CRYPTO') || mission.title.includes('WALLET')) typeHint = 'Blockchain Wallet';
        else if (mission.title.includes('DARK')) typeHint = 'Tor Hidden Service';

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
    // --- BASIC UTILITIES ---
    if (cmd === 'clear') {
      setGameState(prev => ({ ...prev, terminalHistory: [] }));
      return;
    }
    
    // --- UPDATED HELP ---
    if (cmd === 'help') {
      setGameState(prev => ({ 
        ...prev, 
        terminalHistory: [...prev.terminalHistory, { type: 'system', content: 'SYSTEM COMMANDS:\n- missions : List available operations\n- use [id] : Select/Start an operation (e.g. "use m1")\n- exit     : Disconnect from current target\n- clear    : Clear terminal\n\nTACTICAL TOOLS (During Op):\n- nmap [target]\n- curl [url]\n- sqlmap -u [url]\n- msfconsole\n- hydra\n\nACADEMY:\n- learn [topic] : Start AI Tutor class\n- gen ops       : Generate new missions', timestamp: Date.now() }] 
      }));
      return;
    }

    // --- NAVIGATION: LIST MISSIONS ---
    if (cmd === 'missions' || (cmd === 'ls' && !gameState.currentMissionId)) {
        const list = gameState.missions.map(m => 
           `${m.id.padEnd(5)} [${m.completed ? 'COMPLETED' : 'PENDING  '}] ${m.difficulty.padEnd(12)} ${m.title}`
        ).join('\n');
        
        setGameState(prev => ({
            ...prev,
            terminalHistory: [
                ...prev.terminalHistory,
                { type: 'input', content: cmd, timestamp: Date.now() },
                { type: 'output', content: `OPERATIONS DATABASE:\nID    STATUS       DIFFICULTY   TITLE\n--------------------------------------------------\n${list}\n\nType 'use [id]' to engage.`, timestamp: Date.now() }
            ]
        }));
        return;
    }

    // --- NAVIGATION: SELECT MISSION ---
    if (cmd.startsWith('use ')) {
        const targetId = cmd.split(' ')[1];
        setGameState(prev => ({ 
             ...prev, 
             terminalHistory: [...prev.terminalHistory, { type: 'input', content: cmd, timestamp: Date.now() }] 
        }));

        const mission = gameState.missions.find(m => m.id === targetId);
        if (mission) {
            handleSelectMission(mission.id);
        } else {
             setGameState(prev => ({
                 ...prev,
                 terminalHistory: [
                     ...prev.terminalHistory,
                     { type: 'error', content: `ERROR: Mission ID '${targetId}' not found. Use 'missions' to see available IDs.`, timestamp: Date.now() }
                 ]
             }));
        }
        return;
    }

    // --- NAVIGATION: EXIT MISSION ---
    if (cmd === 'exit' || cmd === 'disconnect') {
        setGameState(prev => ({ 
             ...prev, 
             terminalHistory: [...prev.terminalHistory, { type: 'input', content: cmd, timestamp: Date.now() }] 
        }));

        if (gameState.currentMissionId) {
             setGameState(prev => ({
                ...prev,
                currentMissionId: null,
                terminalHistory: [
                    ...prev.terminalHistory,
                    { type: 'system', content: 'Uplink terminated. Returned to root.', timestamp: Date.now() }
                ]
            }));
            setRightPanelMode('tactical');
        } else {
             setGameState(prev => ({
                ...prev,
                terminalHistory: [
                    ...prev.terminalHistory,
                    { type: 'system', content: 'Already at root.', timestamp: Date.now() }
                ]
            }));
        }
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

    // --- MISSION / TARGET INTERACTION (SIMULATED) ---
    if (!gameState.currentMissionId) {
      setGameState(prev => ({ 
        ...prev, 
        terminalHistory: [
            ...prev.terminalHistory, 
            { type: 'input', content: cmd, timestamp: Date.now() },
            { type: 'error', content: 'ERROR: NO TARGET DESIGNATED. Use "missions" to list, "use [id]" to select.', timestamp: Date.now() }
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
        <header className="flex items-center justify-between bg-[#0a0a0a] border border-gray-800 p-3 rounded shrink-0">
            <div className="flex items-center gap-4">
                <div className="w-10 h-10 bg-purple-900/20 border border-purple-500/50 rounded flex items-center justify-center">
                    <Monitor className="text-purple-400" size={20} />
                </div>
                <div>
                    <h1 className="text-2xl font-bold tracking-widest text-white uppercase font-tech">CyberSim <span className="text-purple-500">PRO</span></h1>
                    <div className="flex items-center gap-2 text-[10px] text-gray-500 font-mono">
                        <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                        SYSTEM ONLINE v3.0
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
        <main className="flex-1 grid grid-cols-1 md:grid-cols-12 gap-4 min-h-0 relative">
            {/* Left Panel (Missions) */}
            <div className={`
                ${maximizedPanel === 'mission' ? 'md:col-span-12 z-20 absolute inset-0 bg-[#020202]' : 'md:col-span-3'} 
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
                ${maximizedPanel === 'visualizer' || maximizedPanel === 'terminal' || maximizedPanel === 'tutor' ? 'md:col-span-12 z-20 absolute inset-0 bg-[#020202]' : 'md:col-span-9'}
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