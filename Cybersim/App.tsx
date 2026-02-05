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
    title: 'OP: COLD STORAGE CRACK',
    difficulty: 'Expert',
    description: 'Recover access to a lost Satoshi-era Bitcoin wallet.dat file.',
    objectives: ['Analyze wallet encryption', 'Extract hash', 'Run dictionary attack'],
    targetId: 't1',
    completed: false,
    recommendedTools: ['hashcat', 'john', 'bitcoin2john'],
    briefing: "We've acquired a 'wallet.dat' from a seizure. It contains 50 BTC. The password is believed to be weak. Extract the hash and crack it."
  },
  {
    id: 'm2',
    title: 'OP: SMART CONTRACT AUDIT',
    difficulty: 'Advanced',
    description: 'Identify and exploit a reentrancy vulnerability in a DeFi lending protocol.',
    objectives: ['Scan contract bytecode', 'Identify recursive call', 'Drain testnet funds'],
    targetId: 't2',
    completed: false,
    recommendedTools: ['mythril', 'slither', 'remix'],
    briefing: "Target is 'FlashLoan_Lender.sol'. Source code analysis indicates a state update happens *after* the external call. Demonstrate the reentrancy exploit."
  },
  {
    id: 'm3',
    title: 'OP: LEDGER HIJACK',
    difficulty: 'Expert',
    description: 'Intercept USB packets from a hardware wallet to extract the PIN.',
    objectives: ['Monitor USB traffic', 'Analyze APDU commands', 'Brute force PIN'],
    targetId: 't3',
    completed: false,
    recommendedTools: ['wireshark', 'usbmon', 'btcrecover'],
    briefing: "Target is using a Ledger Nano S. We have a tap on the USB bus. Capture the encrypted APDU packets and attempt to recover the 4-digit PIN."
  },
  {
    id: 'm4',
    title: 'OP: EXCHANGE API LEAK',
    difficulty: 'Intermediate',
    description: 'Access a crypto exchange account via leaked API keys found in a public repo.',
    objectives: ['Validate API Keys', 'Check account balance', 'Exfiltrate withdrawal logs'],
    targetId: 't4',
    completed: false,
    recommendedTools: ['curl', 'ccxt', 'gitrob'],
    briefing: "A developer committed '.env' to GitHub. It contains Binance API keys. Verify if they have 'Withdraw' permissions enabled."
  },
  {
    id: 'm5',
    title: 'OP: PRIVATE KEY HUNT',
    difficulty: 'Beginner',
    description: 'Search a compromised server for unencrypted private keys.',
    objectives: ['Scan filesystem', 'Grep for "BEGIN PRIVATE KEY"', 'Import to Metamask'],
    targetId: 't5',
    completed: false,
    recommendedTools: ['grep', 'find', 'cat'],
    briefing: "We have shell access to a crypto node. The admin is careless. Search the /home directory for any files resembling SSH or Wallet private keys."
  },
  {
    id: 'm6',
    title: 'OP: ETHEREUM NODE SCAN',
    difficulty: 'Intermediate',
    description: 'Scan for open Geth/Parity RPC ports allowing unauthorized admin calls.',
    objectives: ['Scan port 8545', 'Call eth_accounts', 'Attempt personal_unlockAccount'],
    targetId: 't6',
    completed: false,
    recommendedTools: ['nmap', 'metasploit', 'curl'],
    briefing: "Shodan indicates this IP is running an Ethereum Geth node. Check if the RPC port 8545 is exposed to the internet and allows method calls."
  },
  {
    id: 'm7',
    title: 'OP: DARK WEB MARKET',
    difficulty: 'Advanced',
    description: 'De-anonymize a hidden service accepting Monero for illicit goods.',
    objectives: ['Identify backend IP', 'Trace XMR transactions', 'Dump user DB'],
    targetId: 't7',
    completed: false,
    recommendedTools: ['onion-scan', 'xmr-trace', 'nikto'],
    briefing: "The 'SilkRoad 4.0' market is hosting on Tor. They claim to be untraceable. Find the leak in their Nginx configuration."
  }
];

// --- PROCEDURAL MISSION GENERATOR ---
const generateCurriculum = (): Mission[] => {
  const missions: Mission[] = [];
  let idCounter = 100;

  const tracks = [
    { 
      code: 'DEFI', 
      name: 'DEFI_EXPLOITS', 
      tools: ['mythril', 'slither', 'echidna', 'manticore', 'remix'],
      templates: [
        { title: 'REENTRANCY ATTACK', desc: 'Drain contract via recursive withdraw calls.' },
        { title: 'FLASH LOAN ATTACK', desc: 'Manipulate price oracle using flash loan liquidity.' },
        { title: 'INTEGER OVERFLOW', desc: 'Bypass balance checks using uint256 overflow.' },
        { title: 'TX ORIGIN PHISHING', desc: 'Exploit tx.origin authentication flaw.' },
        { title: 'DELEGATECALL HACK', desc: 'Hijack contract state via unsafe delegatecall.' },
        { title: 'TIMESTAMP DEPENDENCY', desc: 'Predict randomness based on block.timestamp.' }
      ]
    },
    { 
      code: 'WALLET', 
      name: 'WALLET_FORENSICS', 
      tools: ['hashcat', 'john', 'btcrecover', 'seed-savior', 'volatility'],
      templates: [
        { title: 'SEED PHRASE BRUTE', desc: 'Recover last 2 words of a BIP39 seed phrase.' },
        { title: 'WALLET.DAT CRACK', desc: 'Crack Bitcoin Core wallet AES-256 encryption.' },
        { title: 'MEMORY DUMP KEYS', desc: 'Extract private keys from RAM dump of a running PC.' },
        { title: 'CLIPBOARD HIJACK', desc: 'Analyze malware replacing crypto addresses in clipboard.' },
        { title: 'BRAINWALLET CRACK', desc: 'Rainbow table attack on low-entropy brainwallets.' }
      ]
    },
    { 
      code: 'CHAIN', 
      name: 'BLOCKCHAIN_INTEL', 
      tools: ['maltego', 'chainalysis', 'dune', 'etherscan', 'nmap'],
      templates: [
        { title: 'RPC PORT EXPOSURE', desc: 'Access unsecured JSON-RPC port 8545/8546.' },
        { title: 'P2P PEER FLOOD', desc: 'Eclipse attack on a Bitcoin node via peer flooding.' },
        { title: '51% ATTACK SIM', desc: 'Simulate hashpower dominance on a testnet chain.' },
        { title: 'MIXER TRACING', desc: 'Trace funds through a coin mixer service.' },
        { title: 'DUSTING ATTACK', desc: 'Identify wallets targeted by dust transactions.' }
      ]
    },
    { 
      code: 'CEX', 
      name: 'EXCHANGE_SECURITY', 
      tools: ['burpsuite', 'ccxt', 'postman', 'wfuzz'],
      templates: [
        { title: 'API KEY LEAK', desc: 'Exploit hardcoded API secret in mobile app binary.' },
        { title: 'ORDER BOOK MANIP', desc: 'Test exchange engine for negative quantity trades.' },
        { title: '2FA BYPASS', desc: 'Bypass TOTP via race condition on withdrawal.' },
        { title: 'KYC DATA EXFIL', desc: 'Access KYC documents via IDOR vulnerability.' }
      ]
    }
  ];

  const difficulties = ['Beginner', 'Intermediate', 'Advanced', 'Expert'];

  // Generate ~40 missions specifically for Crypto
  tracks.forEach(track => {
    for (let i = 0; i < 10; i++) {
        const template = track.templates[i % track.templates.length];
        const difficulty = difficulties[Math.min(Math.floor(i / 3), 3)];
        const targetNum = Math.floor(Math.random() * 8999) + 1000;
        
        missions.push({
            id: `m${idCounter}`,
            title: `OP: ${track.code}-${targetNum} // ${template.title}`,
            difficulty: difficulty as any,
            description: `${template.desc} Target designated as T-${targetNum}.`,
            objectives: ['Establish Uplink', 'Reconnaissance', template.title, 'Exfiltrate/Profit', 'Cover Tracks'],
            targetId: `t${idCounter}`,
            completed: false,
            recommendedTools: [track.tools[i % track.tools.length], track.tools[(i+1) % track.tools.length]],
            briefing: `Operative, new contract available. Sector: ${track.name}. Mission: ${template.desc}. High financial stakes.`
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
    name: 'wallet.dat (Seized)',
    type: TargetType.WORKSTATION,
    ip: 'OFFLINE_FILE',
    os: 'Bitcoin Core v22.0',
    vulnerabilities: ['Weak Encryption'],
    ports: [],
    status: 'online',
    description: 'Encrypted Bitcoin wallet file.'
  },
  't2': {
    id: 't2',
    name: 'FlashLoan_Lender.sol',
    type: TargetType.BLOCKCHAIN,
    ip: '0x7a250d...',
    os: 'EVM (Solidity 0.6.12)',
    vulnerabilities: ['Reentrancy'],
    ports: [],
    status: 'online',
    description: 'DeFi Lending Smart Contract on Ethereum Mainnet.'
  },
  't3': {
    id: 't3',
    name: 'Ledger Nano S',
    type: TargetType.IOT,
    ip: 'USB_DEVICE',
    os: 'BOLOS 2.0',
    vulnerabilities: ['Side-Channel'],
    ports: [],
    status: 'online',
    description: 'Hardware Wallet connected via USB.'
  },
  't4': {
    id: 't4',
    name: 'api.binance-internal.com',
    type: TargetType.WEBSITE,
    ip: '13.225.10.5',
    os: 'AWS Gateway',
    vulnerabilities: ['Leaked Credentials'],
    ports: [443],
    status: 'online',
    description: 'Internal API endpoint for exchange.'
  },
  't5': {
    id: 't5',
    name: 'admin-node-01',
    type: TargetType.SERVER,
    ip: '192.168.1.50',
    os: 'Ubuntu 20.04',
    vulnerabilities: ['Unsecured Files'],
    ports: [22, 80],
    status: 'online',
    description: 'Administrator workstation.'
  },
  't6': {
    id: 't6',
    name: 'Geth-Full-Node',
    type: TargetType.BLOCKCHAIN,
    ip: '54.12.99.102',
    os: 'Linux (Geth)',
    vulnerabilities: ['Open RPC'],
    ports: [30303, 8545],
    status: 'online',
    description: 'Ethereum Node with HTTP-RPC enabled.'
  },
  't7': {
    id: 't7',
    name: 'silkroad4.onion',
    type: TargetType.SERVER,
    ip: '10.200.5.1',
    os: 'Debian (Tor)',
    vulnerabilities: ['Misconfiguration'],
    ports: [80],
    status: 'online',
    description: 'Hidden Marketplace.'
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
    terminalHistory: [{ type: 'system', content: 'CyberSim AI OS v4.0 [CRYPTO_EDITION] Initialized...\nBLOCKCHAIN MODULES LOADED.\nWALLET ANALYZER: ACTIVE.\nType "help" for commands.\nType "missions" to list operations.', timestamp: Date.now() }],
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
      try {
          const audioData = await generateSpeech(text);
          if (audioData) {
            playAudio(audioData);
          } else {
             // Visual feedback if TTS fails
             setGameState(prev => ({ 
                 ...prev, 
                 terminalHistory: [...prev.terminalHistory, { type: 'error', content: '[AUDIO ERROR] Speech synthesis uplink failed. Check network or retry.', timestamp: Date.now() }]
             }));
          }
      } catch (e) {
         console.error("Speak error", e);
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
        
        let typeHint = 'Server';
        if (mission.title.includes('DEFI') || mission.title.includes('CONTRACT')) typeHint = 'Smart Contract';
        else if (mission.title.includes('WALLET') || mission.title.includes('KEY')) typeHint = 'Crypto Wallet';
        else if (mission.title.includes('CHAIN') || mission.title.includes('NODE')) typeHint = 'Blockchain Node';
        else if (mission.title.includes('EXCHANGE') || mission.title.includes('API')) typeHint = 'Exchange API';
        
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
        { type: 'system', content: `\n// LOADING CRYPTO OP: ${mission.title}...\n// BRIEFING: ${mission.briefing}`, timestamp: Date.now() }
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
          speak("Class dismissed. Practice these concepts on the simulated targets.");
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
        terminalHistory: [...prev.terminalHistory, { type: 'system', content: 'CRYPTO OPS COMMANDS:\n- missions : List available operations\n- use [id] : Select/Start an operation (e.g. "use m1")\n- exit     : Disconnect\n- clear    : Clear terminal\n\nCRYPTO TOOLS:\n- mythril [file.sol] : Analyze Smart Contract\n- slither [file.sol] : Static analysis\n- hashcat -m 0 [hash]: Crack MD5/Wallet hashes\n- cast call [addr]   : Ethereum RPC call\n- btc-recover        : Recover lost seeds\n\nACADEMY:\n- learn [topic] : Start AI Tutor class\n- gen ops       : Generate new missions', timestamp: Date.now() }] 
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
    const isScan = cmd.includes('nmap') || cmd.includes('scan') || cmd.includes('mythril');
    const isAttack = cmd.includes('exploit') || cmd.includes('hashcat') || cmd.includes('slither');
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
                        CRYPTO WARFARE v4.0
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