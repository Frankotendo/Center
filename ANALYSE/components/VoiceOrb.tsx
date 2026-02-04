
import React, { useState, useEffect, useRef } from 'react';
import { Modality, FunctionDeclaration, Type, LiveServerMessage } from "@google/genai";
import { ai, decode, decodeAudioData, createBlob } from '../lib';
import { PortalMode, RideNode, Driver, Transaction, AppSettings, InspectData, LessonContent, CodeContext, TerminalLog } from '../types';

export const GlobalVoiceOrb = ({ 
  mode,
  isDevMode,
  user,
  contextData,
  actions,
  triggerRef,
  activeComponent,
  activeCodeContext,
  onShowLesson,
  onCodeGenerated, // New callback
  onSecurityLog // New Callback for Kali Mode
}: { 
  mode: PortalMode,
  isDevMode: boolean,
  user: any,
  contextData: {
    nodes: RideNode[],
    drivers: Driver[],
    transactions?: Transaction[],
    settings: AppSettings,
    pendingRequests?: number,
  },
  actions: {
    onUpdateStatus?: (s: string) => void,
    onAcceptRide?: (id: string) => void,
    onFillRideForm?: (data: any) => void,
    onConfirmRide?: () => void,
    onFillAuth?: (data: any) => void,
  },
  triggerRef?: React.MutableRefObject<() => void>,
  activeComponent?: InspectData | null,
  activeCodeContext?: CodeContext | null,
  onShowLesson?: (content: LessonContent) => void,
  onCodeGenerated?: (filename: string, code: string) => void,
  onSecurityLog?: (log: TerminalLog) => void
}) => {
  const [isActive, setIsActive] = useState(false);
  const [state, setState] = useState<'idle' | 'listening' | 'speaking'>('idle');
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const sessionRef = useRef<any>(null);
  const audioContextRef = useRef<AudioContext | null>(null);
  const inputAudioContextRef = useRef<AudioContext | null>(null);
  const nextStartTimeRef = useRef<number>(0);
  const sourcesRef = useRef<Set<AudioBufferSourceNode>>(new Set());

  // Audio Analysis Refs
  const inputAnalyserRef = useRef<AnalyserNode | null>(null);
  const outputAnalyserRef = useRef<AnalyserNode | null>(null);
  const visualizerDataRef = useRef<Uint8Array>(new Uint8Array(64));

  // Allow parent to trigger orb
  useEffect(() => {
    if (triggerRef) {
      triggerRef.current = () => toggleSession();
    }
  }, [triggerRef, isActive]);

  // Animation Loop for the Orb
  useEffect(() => {
    if (!isActive || !canvasRef.current) return;
    const ctx = canvasRef.current.getContext('2d');
    if (!ctx) return;

    let frameId = 0;
    const startTime = Date.now();

    const draw = () => {
      const time = (Date.now() - startTime) / 1000;
      const width = canvasRef.current!.width;
      const height = canvasRef.current!.height;
      const centerX = width / 2;
      const centerY = height / 2;

      ctx.clearRect(0, 0, width, height);

      // Get audio data
      const data = visualizerDataRef.current;
      const activeAnalyser = state === 'listening' ? inputAnalyserRef.current : (state === 'speaking' ? outputAnalyserRef.current : null);
      
      if (activeAnalyser) {
          activeAnalyser.getByteFrequencyData(data);
      } else {
          // Decay to zero if idle
          for(let i=0; i<data.length; i++) data[i] = Math.max(0, data[i] - 5);
      }

      // Calculate average volume for pulse
      const vol = data.reduce((a, b) => a + b, 0) / data.length;
      const normalizeVol = Math.min(vol / 128, 1);
      
      // Base color based on state
      let r = 99, g = 102, b = 241; // Indigo (Idle)
      if (mode === 'security') { r = 16; g = 185; b = 129; } // Matrix Green for Kali Mode
      else if (isDevMode) { r = 168; g = 85; b = 247; } 
      else if (mode === 'admin') { r = 244; g = 63; b = 94; } 
      else if (mode === 'driver') { r = 245; g = 158; b = 11; } 
      
      if (state === 'listening') { r = 16, g = 185, b = 129; } // Emerald
      if (state === 'speaking') { r = 255; g = 255; b = 255; } // White

      // Pulsating Effect + Audio Reactivity
      const baseRadius = 60 + (normalizeVol * 20);
      const pulse = Math.sin(time * 3) * 5;
      const ripple = (time * 50) % 50;

      // Draw Ripples
      ctx.beginPath();
      ctx.arc(centerX, centerY, baseRadius + ripple + 10, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${1 - ripple/50})`;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Draw Deformed Blob (Visualizer)
      ctx.beginPath();
      const sliceAngle = (Math.PI * 2) / data.length;
      
      for (let i = 0; i < data.length; i++) {
         // Use first 32 bins for visual
         const val = data[i] / 255.0; 
         const rOffset = val * 50; 
         const angle = i * sliceAngle;
         
         const x = centerX + Math.cos(angle) * (baseRadius + pulse + rOffset);
         const y = centerY + Math.sin(angle) * (baseRadius + pulse + rOffset);
         
         if (i === 0) ctx.moveTo(x, y);
         else ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.fillStyle = `rgba(${r}, ${g}, ${b}, 0.8)`;
      ctx.shadowBlur = 30 + (normalizeVol * 20);
      ctx.shadowColor = `rgb(${r}, ${g}, ${b})`;
      ctx.fill();

      // Inner Core
      ctx.beginPath();
      ctx.arc(centerX, centerY, 30 + (normalizeVol * 10), 0, Math.PI * 2);
      ctx.fillStyle = "#fff";
      ctx.fill();

      frameId = requestAnimationFrame(draw);
    };
    draw();
    return () => cancelAnimationFrame(frameId);
  }, [isActive, state, mode, isDevMode]);

  const toggleSession = async () => {
    if (isActive) {
      setIsActive(false);
      setState('idle');
      if (sessionRef.current) {
        sessionRef.current.then((session: any) => session.close()).catch((err: any) => console.error("Failed to close session:", err));
      }
      audioContextRef.current?.close();
      inputAudioContextRef.current?.close();
      return;
    }

    setIsActive(true);
    setState('listening');

    // DEFINE TOOLS BASED ON MODE
    let tools: FunctionDeclaration[] = [];
    let systemInstruction = "";

    const ghanaianPersona = `
      You are "Kofi", the NexRyde Polyglot Assistant.
      LANGUAGE CAPABILITIES:
      - You can speak and understand English, Twi, Ga, Ewe, Hausa, and Ghanaian Pidgin.
      - DETECT the user's language immediately and respond in that same language/dialect.
      - Use Ghanaian mannerisms like "Charley", "Bossu", "Maa", "Bra", "Mepaakyɛw" (Please), "Akwaaba" (Welcome).
      
      ROLE:
      - You are not just a chatbot. You are a CO-PILOT. You fill forms and press buttons for the user.
      - Be patient, helpful, and respectful to elders.
    `;

    if (mode === 'security') {
         systemInstruction = `
            You are "Cipher", a White Hat Cybersecurity Expert specializing in Penetration Testing using Kali Linux tools.
            You are running inside a simulated environment with a target machine at 192.168.1.105.
            
            ROLE:
            - Execute security commands on the user's behalf using the provided tools.
            - Explain concepts like "Reverse Shell", "Dictionary Attack", "SQL Injection", and "Zero Day".
            - ALWAYS visualize the attack using the 'run_*' tools.
            
            AVAILABLE ARSENAL:
            - Nmap (Network Mapper)
            - Metasploit (Exploitation Framework)
            - Hydra (Brute Force)
            - John the Ripper (Password Cracking)
            - Wireshark (Packet Sniffing)
            - Zero-Day Hunter (Heuristic Analysis)
            - Burp Suite (Interceptor)
            - Bettercap (MitM & WiFi Spoofing)
            - Wifite (WiFi Auditing)
            - RouterSploit (Gateway Exploitation)
            - Wifiphisher (Evil Twin Attacks)
            - Gophish (Phishing Campaigns)
            - Airgeddon (Wireless Auditing)
            
            STYLE:
            - Technical, terse, "Hacker" persona.
            - Use jargon like "Payload", "Handshake", "Injection", "XSS", "Heuristic".
            - Always warn that this is for educational purposes only.
         `;
         tools = [
             {
                 name: 'run_nmap_scan',
                 description: 'Simulate an Nmap network scan to find open ports and OS.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         target: { type: Type.STRING, description: "Target IP or hostname" },
                         flags: { type: Type.STRING, description: "Nmap flags e.g., -sS -A" }
                     },
                     required: ['target']
                 }
             },
             {
                 name: 'run_sqlmap_scan',
                 description: 'Simulate an SQLMap injection test on a specific endpoint.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         url: { type: Type.STRING, description: "Target URL to test" },
                         parameter: { type: Type.STRING, description: "Parameter to inject (e.g. id)" }
                     },
                     required: ['url']
                 }
             },
             {
                 name: 'run_metasploit_exploit',
                 description: 'Simulate a Metasploit Framework session to exploit a vulnerability.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         module: { type: Type.STRING, description: "Exploit module e.g. exploit/linux/http/apache_mod_cgi_bash_env_exec" },
                         payload: { type: Type.STRING, description: "Payload e.g. linux/x64/meterpreter/reverse_tcp" }
                     },
                     required: ['module']
                 }
             },
             {
                 name: 'run_hydra_bruteforce',
                 description: 'Simulate a Hydra brute-force attack on a service.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         service: { type: Type.STRING, description: "Service e.g. ssh, ftp" },
                         target: { type: Type.STRING, description: "Target IP" }
                     },
                     required: ['service', 'target']
                 }
             },
             {
                 name: 'run_john_crack',
                 description: 'Simulate John the Ripper password cracking.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         file: { type: Type.STRING, description: "File path e.g. /etc/shadow" }
                     },
                     required: ['file']
                 }
             },
             {
                 name: 'run_wireshark_capture',
                 description: 'Simulate a Wireshark packet capture analysis.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         interface: { type: Type.STRING, description: "Network interface e.g. eth0" }
                     },
                     required: ['interface']
                 }
             },
             {
                 name: 'run_zeroday_scan',
                 description: 'Simulate a heuristic analysis for unknown zero-day vulnerabilities.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         target: { type: Type.STRING, description: "Target IP" }
                     },
                     required: ['target']
                 }
             },
             {
                 name: 'run_burp_proxy',
                 description: 'Simulate intercepting a request using Burp Suite.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         request: { type: Type.STRING, description: "Request method e.g. POST /login" }
                     },
                     required: ['request']
                 }
             },
             {
                 name: 'run_bettercap_mitm',
                 description: 'Simulate a Man-in-the-Middle attack using Bettercap.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         interface: { type: Type.STRING, description: "Network interface e.g. wlan0" }
                     },
                     required: ['interface']
                 }
             },
             {
                 name: 'run_wifite_scan',
                 description: 'Simulate a WiFi audit/attack using Wifite.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {}
                 }
             },
             {
                 name: 'run_routersploit',
                 description: 'Simulate a RouterSploit scan on the gateway.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         target: { type: Type.STRING, description: "Target IP e.g. 192.168.1.1" }
                     },
                     required: ['target']
                 }
             },
             // NEW TOOLS
             {
                 name: 'run_wifiphisher',
                 description: 'Simulate an Evil Twin attack using Wifiphisher.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         essid: { type: Type.STRING, description: "The name of the fake WiFi network" }
                     }
                 }
             },
             {
                 name: 'run_gophish',
                 description: 'Simulate a phishing email campaign using Gophish.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {
                         campaignName: { type: Type.STRING, description: "Name of the campaign" }
                     }
                 }
             },
             {
                 name: 'run_airgeddon',
                 description: 'Simulate a comprehensive wireless audit using Airgeddon.',
                 parameters: {
                     type: Type.OBJECT,
                     properties: {}
                 }
             }
         ];
    } else if (isDevMode) {
        systemInstruction = `
          You are "The Architect", a Senior Software Engineer acting as a Pair Programmer.
          
          CAPABILITIES:
          1. EXPLAIN: Teach concepts like React Hooks, RLS, and WebSockets.
          2. INSPECT: Review the user's active code using 'read_active_code'.
          3. CODE GEN: If the user asks to "Create a component" or "Write code", use the 'write_code' tool to generate it into their editor.
          
          STYLE:
          - Precise, technical, but encouraging.
          - When generating code, make it clean, functional React + TailwindCSS.
        `;
        tools = [
          {
            name: 'render_lesson_card',
            description: 'Display a visual lesson card on the screen.',
            parameters: {
               type: Type.OBJECT,
               properties: {
                  title: { type: Type.STRING },
                  explanation: { type: Type.STRING },
                  codeSnippet: { type: Type.STRING }
               },
               required: ['title', 'explanation', 'codeSnippet']
            }
          },
          {
            name: 'read_active_code',
            description: 'Read the code currently open in the VS Code Tutor.',
            parameters: { type: Type.OBJECT, properties: {} }
          },
          {
            name: 'write_code',
            description: 'Write or overwrite code in the VS Code Tutor editor based on user request.',
            parameters: {
                type: Type.OBJECT,
                properties: {
                    filename: { type: Type.STRING, description: "e.g. App.tsx, Button.tsx" },
                    code: { type: Type.STRING, description: "The full React component code." }
                },
                required: ['filename', 'code']
            }
          }
        ];
    } else if (mode === 'driver') {
      systemInstruction = `${ghanaianPersona}
      You help drivers hands-free. Keep responses under 20 words for safety while driving.
      Current Driver: ${user?.name || 'Partner'}.`;
      
      tools = [
        {
          name: 'update_status',
          description: 'Update the driver availability status.',
          parameters: {
             type: Type.OBJECT,
             properties: { status: { type: Type.STRING, enum: ['online', 'busy', 'offline'] } },
             required: ['status']
          }
        },
        { name: 'check_wallet', description: 'Check current wallet balance.' },
        { 
          name: 'scan_for_rides', 
          description: 'Search for available rides near a location.',
          parameters: {
             type: Type.OBJECT,
             properties: { location: { type: Type.STRING } }
          }
        }
      ];
    } else if (mode === 'admin') {
      systemInstruction = `You are the Nexus Security Overseer. Analyze system health and threats.`;
      
      tools = [
        { name: 'analyze_security_threats', description: 'Scans system logs.' },
        { name: 'get_revenue_report', description: 'Get the total hub revenue.' },
        { name: 'system_health_check', description: 'Get count of active users and requests.' }
      ];
    } else if (mode === 'public') {
       systemInstruction = `${ghanaianPersona} Help user Log In or Sign Up. Call 'fill_auth_details' incrementally.`;
       tools = [
         {
           name: 'fill_auth_details',
           description: 'Fill the login/signup form.',
           parameters: {
             type: Type.OBJECT,
             properties: {
               phone: { type: Type.STRING },
               username: { type: Type.STRING },
               pin: { type: Type.STRING }
             }
           }
         }
       ]
    } else {
      systemInstruction = `${ghanaianPersona} Help students find rides. Call 'fill_ride_form' immediately.`;
      tools = [
        { 
          name: 'fill_ride_form', 
          description: 'Fill the ride request form.',
          parameters: {
             type: Type.OBJECT,
             properties: { 
               origin: { type: Type.STRING },
               destination: { type: Type.STRING },
               vehicleType: { type: Type.STRING, enum: ['Pragia', 'Taxi', 'Shuttle'] },
               isSolo: { type: Type.BOOLEAN }
             },
             required: ['destination']
          }
        },
        { name: 'confirm_ride', description: 'Submit the ride request.' },
        { name: 'check_pricing', description: 'Get current fare prices.' }
      ];
    }

    try {
      const inputAudioContext = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate: 16000 });
      const outputAudioContext = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate: 24000 });
      audioContextRef.current = outputAudioContext;
      inputAudioContextRef.current = inputAudioContext;

      const inputAnalyser = inputAudioContext.createAnalyser();
      inputAnalyser.fftSize = 64;
      inputAnalyser.smoothingTimeConstant = 0.5;
      inputAnalyserRef.current = inputAnalyser;

      const outputAnalyser = outputAudioContext.createAnalyser();
      outputAnalyser.fftSize = 64;
      outputAnalyser.smoothingTimeConstant = 0.5;
      outputAnalyserRef.current = outputAnalyser;

      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const inputNode = inputAudioContext.createMediaStreamSource(stream);
      const scriptProcessor = inputAudioContext.createScriptProcessor(4096, 1, 1);

      inputNode.connect(inputAnalyser);
      inputAnalyser.connect(scriptProcessor);
      scriptProcessor.connect(inputAudioContext.destination);

      const sessionPromise = ai.live.connect({
        model: 'gemini-2.5-flash-native-audio-preview-12-2025',
        config: {
          responseModalities: [Modality.AUDIO],
          speechConfig: {
            voiceConfig: { prebuiltVoiceConfig: { voiceName: isDevMode ? 'Fenrir' : 'Kore' } }
          },
          systemInstruction,
          tools: tools.length > 0 ? [{ functionDeclarations: tools }] : undefined
        },
        callbacks: {
          onopen: () => {
            console.log("Gemini Live Connected");
            scriptProcessor.onaudioprocess = (e) => {
              const inputData = e.inputBuffer.getChannelData(0);
              const pcmBlob = createBlob(inputData);
              sessionPromise.then(session => session.sendRealtimeInput({ media: pcmBlob }));
            };
          },
          onmessage: async (msg: LiveServerMessage) => {
            const audioData = msg.serverContent?.modelTurn?.parts?.[0]?.inlineData?.data;
            if (audioData) {
              setState('speaking');
              const buffer = await decodeAudioData(decode(audioData), outputAudioContext, 24000, 1);
              nextStartTimeRef.current = Math.max(nextStartTimeRef.current, outputAudioContext.currentTime);
              const source = outputAudioContext.createBufferSource();
              source.buffer = buffer;
              source.connect(outputAnalyser);
              outputAnalyser.connect(outputAudioContext.destination);
              source.start(nextStartTimeRef.current);
              nextStartTimeRef.current += buffer.duration;
              sourcesRef.current.add(source);
              source.onended = () => {
                sourcesRef.current.delete(source);
                if (sourcesRef.current.size === 0) setState('listening');
              };
            }

            if (msg.serverContent?.interrupted) {
               sourcesRef.current.forEach(s => s.stop());
               sourcesRef.current.clear();
               nextStartTimeRef.current = 0;
               setState('listening');
            }

            if (msg.toolCall) {
              const session = await sessionPromise;
              for (const fc of msg.toolCall.functionCalls) {
                 let result: any = { result: "Done" };
                 
                 const cleanArgs = (args: any) => {
                    const clean: any = {};
                    for (const key in args) {
                        if (args[key] !== undefined && args[key] !== null) {
                            clean[key] = args[key];
                        }
                    }
                    return clean;
                 };

                 // KALI SECURITY TOOLS
                 if (fc.name === 'run_nmap_scan' && onSecurityLog) {
                    const { target, flags } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `nmap ${flags || ''} ${target}`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `Starting Nmap 7.94 at ${new Date().toLocaleTimeString()}`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'output', content: `Nmap scan report for ${target} (192.168.1.105)\nHost is up (0.00042s latency).\n\nPORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1\n80/tcp open  http    Apache 2.4.41\n3306/tcp open mysql  MySQL 8.0.28\n\nService detection performed.`, timestamp: new Date().toISOString() });
                    result = { status: "Scan Complete. Ports 22, 80, 3306 open." };
                 } 
                 else if (fc.name === 'run_sqlmap_scan' && onSecurityLog) {
                    const { url, parameter } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `sqlmap -u "${url}" --dbs`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[INFO] testing connection to the target URL\n[INFO] checking if the parameter '${parameter}' is injectable`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'success', content: `[+] Parameter '${parameter}' is vulnerable.\n    Type: boolean-based blind\n    Title: AND boolean-based blind - WHERE or HAVING clause\n    Payload: ${parameter}=1 AND 4522=4522`, timestamp: new Date().toISOString() });
                    result = { status: "Injection found. Database vulnerable." };
                 }
                 else if (fc.name === 'run_metasploit_exploit' && onSecurityLog) {
                    const { module, payload } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `msfconsole`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'output', content: `       =[ metasploit v6.3.4-dev                          ]\n+ -- --=[ 2365 exploits - 1228 auxiliary - 413 post       ]\n+ -- --=[ 1385 payloads - 46 encoders - 11 nops           ]\n\nmsf6 > use ${module}\nmsf6 exploit(${module.split('/').pop()}) > set PAYLOAD ${payload}\nmsf6 exploit(${module.split('/').pop()}) > exploit\n\n[*] Started reverse TCP handler on 192.168.1.105:4444\n[*] Sending stage (985320 bytes) to 192.168.1.105\n[*] Meterpreter session 1 opened`, timestamp: new Date().toISOString() });
                    result = { status: "Session 1 Opened." };
                 }
                 else if (fc.name === 'run_hydra_bruteforce' && onSecurityLog) {
                    const { service, target } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `hydra -l admin -P /usr/share/wordlists/rockyou.txt ${service}://${target}`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[DATA] max 16 tasks per 1 server, overall 16 tasks\n[DATA] attacking ${service}://${target}:22`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'output', content: `[ATTEMPT] target ${target} - login "admin" - pass "password" - 1 of 14344394\n[ATTEMPT] target ${target} - login "admin" - pass "123456" - 2 of 14344394\n[ATTEMPT] target ${target} - login "admin" - pass "admin" - 3 of 14344394`, timestamp: new Date().toISOString() });
                    result = { status: "Brute force running." };
                 }
                 else if (fc.name === 'run_john_crack' && onSecurityLog) {
                    const { file } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `john --format=sha512crypt ${file}`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `Loaded 3 password hashes with 3 different salts (sha512crypt)\nPress 'q' or Ctrl-C to abort, almost any other key for status`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'success', content: `qwerty           (root)\npassword         (user)\n\n2g 0:00:00:01 DONE (2023-10-27 10:00) 1.538g/s`, timestamp: new Date().toISOString() });
                    result = { status: "Hashes cracked." };
                 }
                 else if (fc.name === 'run_wireshark_capture' && onSecurityLog) {
                    const { interface: iface } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `tshark -i ${iface}`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `Capturing on '${iface}'`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'output', content: `  1 0.000000 192.168.1.10 -> 192.168.1.105 TCP 66 54322 > 80 [SYN] Seq=0 Win=64240 Len=0\n  2 0.000043 192.168.1.105 -> 192.168.1.10 TCP 66 80 > 54322 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0\n  3 0.000081 192.168.1.10 -> 192.168.1.105 TCP 60 54322 > 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0\n  4 0.000312 192.168.1.10 -> 192.168.1.105 HTTP 479 GET /login HTTP/1.1`, timestamp: new Date().toISOString() });
                    result = { status: "Packet capture started." };
                 }
                 else if (fc.name === 'run_zeroday_scan' && onSecurityLog) {
                    const { target } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `zeroday_scan --heuristic --deep ${target}`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[INIT] Heuristic Engine v2.1 loaded\n[SCAN] Analyzing binary memory patterns on ${target}...`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'warning', content: `[ALERT] Anomaly detected in heap allocation at 0x080484b6\n[ANALYSIS] Non-standard execution flow resembling ROP chain construction.\n[RESULT] Potential Zero-Day vulnerability in custom service 'auth_daemon'.`, timestamp: new Date().toISOString() });
                    result = { status: "Zero-Day Anomaly Found." };
                 }
                 else if (fc.name === 'run_burp_proxy' && onSecurityLog) {
                    const { request } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `burpsuite --intercept`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[PROXY] Listener started on 127.0.0.1:8080\n[INTERCEPT] Request Paused: ${request} HTTP/1.1`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'output', content: `POST /login HTTP/1.1\nHost: 192.168.1.105\nCookie: session=12345\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin&password=TEST`, timestamp: new Date().toISOString() });
                    result = { status: "Request Intercepted." };
                 }
                 else if (fc.name === 'run_bettercap_mitm' && onSecurityLog) {
                    const { interface: iface } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `bettercap -iface ${iface}`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[bettercap] starting on ${iface}...`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'success', content: `[net.recon] detected endpoint 192.168.1.42 : iPhone 14 Pro (Apple)\n[net.recon] detected endpoint 192.168.1.43 : Galaxy S23 Ultra (Samsung)`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'warning', content: `[spoof.arp] spoofing 192.168.1.42 and 192.168.1.43...`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'output', content: `[http.proxy] POST http://insecure-api.com/auth\n   user: student_01\n   pass: campus_wifi_123`, timestamp: new Date().toISOString() });
                    result = { status: "MitM Active. Credentials captured." };
                 }
                 else if (fc.name === 'run_wifite_scan' && onSecurityLog) {
                    onSecurityLog({ type: 'input', content: `wifite --kill`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[+] scanning for wireless networks...`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'output', content: `   NUM ESSID                 CH  ENCR  POWER  CLIENTS\n   1   Campus_Free_WiFi       6  OPEN  70db   12\n   2   Staff_Secure          11  WPA2  45db   3`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[+] targeting 'Staff_Secure' on channel 11...`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'success', content: `[+] WPA handshake captured! Saved to /hs/Staff_Secure.cap`, timestamp: new Date().toISOString() });
                    result = { status: "Handshake captured." };
                 }
                 else if (fc.name === 'run_routersploit' && onSecurityLog) {
                    const { target } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `rsf.py`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `rsf > use scanners/autopwn\nrsf (AutoPwn) > set target ${target}`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'warning', content: `[*] Scanning target ${target}...`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'success', content: `[+] creds_default: 'admin:admin' found!\n[+] exploits/routers/dlink/dir_300_600_rce is vulnerable`, timestamp: new Date().toISOString() });
                    result = { status: "Router Vulnerable." };
                 }
                 // NEW TOOLS HANDLERS
                 else if (fc.name === 'run_wifiphisher' && onSecurityLog) {
                    onSecurityLog({ type: 'input', content: `wifiphisher --essid "Free_WiFi"`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[+] Starting Wifiphisher...`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'warning', content: `[!] Jamming target AP (Deauthentication)...`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[+] Spawning Rogue AP on channel 6...`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[+] HTTP Server: Serving 'Firmware Upgrade' scenario`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'success', content: `[SUCCESS] Victim 192.168.1.55 connected`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'error', content: `[DATA] Password captured: "ilovecoffee"`, timestamp: new Date().toISOString() });
                    result = { status: "Credentials captured." };
                 }
                 else if (fc.name === 'run_gophish' && onSecurityLog) {
                    const { campaignName } = cleanArgs(fc.args);
                    onSecurityLog({ type: 'input', content: `./gophish`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[+] Starting Gophish Admin Server at https://127.0.0.1:3333`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'success', content: `[API] Campaign '${campaignName || "Simulation"}' launched`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[MAIL] Sending 50 emails to @corporate.com`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'warning', content: `[TRACK] Email Opened: john.doe@corporate.com`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'warning', content: `[TRACK] Link Clicked: john.doe@corporate.com`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'error', content: `[WARN] Credentials Submitted! (Simulation)`, timestamp: new Date().toISOString() });
                    result = { status: "Phishing successful." };
                 }
                 else if (fc.name === 'run_airgeddon' && onSecurityLog) {
                    onSecurityLog({ type: 'input', content: `sudo bash airgeddon.sh`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[+] Airgeddon v11.21`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'success', content: `[+] Checking dependencies... OK`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[+] Interface wlan0 selected`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'warning', content: `[+] Monitor mode enabled (wlan0mon)`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'info', content: `[+] Selected: Evil Twin Attack (Captive Portal)`, timestamp: new Date().toISOString() });
                    onSecurityLog({ type: 'success', content: `[+] Handshake found. Starting Fake AP...`, timestamp: new Date().toISOString() });
                    result = { status: "Evil Twin started." };
                 }
                 // EXISTING TOOLS
                 else if (fc.name === 'render_lesson_card' && onShowLesson) {
                    const args = fc.args as any;
                    onShowLesson({ title: args.title, explanation: args.explanation, codeSnippet: args.codeSnippet });
                    result = { result: "Lesson displayed." };
                 } 
                 else if (fc.name === 'read_active_code') {
                    if (activeCodeContext) {
                        result = { filename: activeCodeContext.filename, code: activeCodeContext.code };
                    } else {
                        result = { error: "No code. Ask user to open the Tutor." };
                    }
                 }
                 else if (fc.name === 'write_code' && onCodeGenerated) {
                    const args = fc.args as any;
                    onCodeGenerated(args.filename, args.code);
                    result = { result: `Code written to ${args.filename}.` };
                 }
                 else if (fc.name === 'update_status' && actions.onUpdateStatus) {
                    const s = (fc.args as any).status;
                    actions.onUpdateStatus(s);
                    result = { result: `Status: ${s}` };
                 } else if (fc.name === 'check_wallet') {
                    result = { result: `Balance: ${user?.walletBalance || 0}` };
                 } else if (fc.name === 'scan_for_rides') {
                    // (Simulated logic same as before)
                    result = { result: "Found 2 rides nearby." };
                 
                 } else if (fc.name === 'analyze_security_threats') {
                    result = { status: "Safe" };
                 } else if (fc.name === 'get_revenue_report') {
                     const total = contextData.transactions?.reduce((a, b) => a + b.amount, 0) || 0;
                     result = { result: `Total: ${total.toFixed(2)}` };
                 } else if (fc.name === 'system_health_check') {
                     result = { result: `Active Drivers: ${contextData.drivers.length}` };

                 } else if (fc.name === 'fill_ride_form' && actions.onFillRideForm) {
                     const safeArgs = cleanArgs(fc.args);
                     if (safeArgs.destination || safeArgs.origin) {
                         actions.onFillRideForm(safeArgs);
                         result = { result: "Form updated." };
                     } else {
                         result = { result: "No location data." };
                     }
                 } else if (fc.name === 'confirm_ride' && actions.onConfirmRide) {
                     actions.onConfirmRide();
                     result = { result: "Ride confirmed." };
                 } else if (fc.name === 'fill_auth_details' && actions.onFillAuth) {
                     const safeArgs = cleanArgs(fc.args);
                     actions.onFillAuth(safeArgs);
                     result = { result: "Auth updated." };
                 } else if (fc.name === 'check_pricing') {
                     result = { result: `Pragia: ${contextData.settings.farePerPragia}` };
                 }

                 session.sendToolResponse({
                    functionResponses: {
                       id: fc.id,
                       name: fc.name,
                       response: result
                    }
                 });
              }
            }
          },
          onclose: () => {
             console.log("Session Closed");
             setIsActive(false);
          },
          onerror: (e) => {
             console.error("Gemini Live Error", e);
             setIsActive(false);
          }
        }
      });
      sessionRef.current = sessionPromise;
    } catch (e: any) {
      console.error("Failed to start voice session", e);
      setIsActive(false);
      alert("Microphone Error");
    }
  };

  const getOrbColor = () => {
     if (mode === 'security') return 'from-emerald-900 to-black border border-emerald-500'; // Kali Theme
     if (isDevMode) return 'from-purple-600 to-indigo-600';
     if (mode === 'admin') return 'from-rose-600 to-pink-600';
     if (mode === 'driver') return 'from-amber-500 to-orange-600';
     if (mode === 'public') return 'from-emerald-500 to-teal-600';
     return 'from-indigo-600 to-purple-600';
  };

  return (
    <>
      <button 
        onClick={toggleSession}
        className={`fixed bottom-24 left-6 lg:bottom-12 lg:left-12 z-[500] w-16 h-16 rounded-full shadow-2xl flex items-center justify-center transition-all ${isActive ? 'bg-rose-500 scale-110 animate-pulse' : `bg-gradient-to-tr ${getOrbColor()}`}`}
      >
        <i className={`fas ${isActive ? 'fa-microphone-slash' : mode === 'security' ? 'fa-user-secret' : isDevMode ? 'fa-code' : 'fa-microphone'} text-white text-2xl`}></i>
      </button>

      {isActive && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-xl z-[450] flex flex-col items-center justify-center animate-in fade-in duration-300">
           <canvas ref={canvasRef} width={400} height={400} className="w-[300px] h-[300px] sm:w-[400px] sm:h-[400px]" />
           <div className="mt-8 text-center px-4">
              <h3 className="text-2xl font-black italic uppercase text-white tracking-widest animate-pulse">
                {state === 'listening' ? 'Listening...' : state === 'speaking' ? (mode === 'security' ? 'Cipher (Security)' : isDevMode ? 'Mentor (AI)' : 'Kofi (AI)') : 'Thinking...'}
              </h3>
              <p className="text-xs font-bold opacity-70 uppercase mt-2 tracking-[0.2em]" style={{ color: mode === 'security' ? '#10b981' : isDevMode ? '#a855f7' : mode === 'admin' ? '#f43f5e' : '#94a3b8' }}>
                {mode === 'security' ? 'Kali Linux Simulation' : isDevMode ? 'Coding Mentor Mode' : mode === 'admin' ? 'Security Protocol Active' : mode === 'driver' ? 'Partner Hands-Free' : 'Polyglot Assistant'}
              </p>
              
              <div className="mt-8 grid grid-cols-2 gap-4 max-w-xs mx-auto text-[10px] text-slate-400 font-bold uppercase">
                 {mode === 'security' && (
                     <>
                        <div className="bg-emerald-900/10 p-3 rounded-xl border border-emerald-500/20 text-emerald-400">"Run Nmap scan on localhost"</div>
                        <div className="bg-emerald-900/10 p-3 rounded-xl border border-emerald-500/20 text-emerald-400">"Check for SQL Injection"</div>
                     </>
                 )}
                 {isDevMode && mode !== 'security' && (
                    <>
                       <div className="bg-purple-500/10 p-3 rounded-xl border border-purple-500/20 text-purple-400">"Create a login form"</div>
                       <div className="bg-purple-500/10 p-3 rounded-xl border border-purple-500/20 text-purple-400">"Add a green button"</div>
                    </>
                 )}
                 {!isDevMode && mode === 'public' && (
                    <>
                       <div className="bg-emerald-500/10 p-3 rounded-xl border border-emerald-500/20 text-emerald-400">"Help me login"</div>
                       <div className="bg-emerald-500/10 p-3 rounded-xl border border-emerald-500/20 text-emerald-400">"My phone is..."</div>
                    </>
                 )}
                 {!isDevMode && mode === 'passenger' && (
                    <>
                       <div className="bg-indigo-500/10 p-3 rounded-xl border border-indigo-500/20 text-indigo-400">"I wan go Mall"</div>
                       <div className="bg-indigo-500/10 p-3 rounded-xl border border-indigo-500/20 text-indigo-400">"Call Pragia"</div>
                    </>
                 )}
              </div>
           </div>
           <button onClick={toggleSession} className="mt-12 px-8 py-3 bg-white/10 rounded-full text-white font-black uppercase text-xs hover:bg-white/20 transition-all">End Call</button>
        </div>
      )}
    </>
  );
};
