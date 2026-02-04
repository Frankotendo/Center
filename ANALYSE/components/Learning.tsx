
import React, { useState, useEffect, useRef } from 'react';
import { InspectData, LessonContent, TerminalLog, SecurityTarget, SecurityTool, KillChainStep } from '../types';

// --- Improved Syntax Highlighting ---
const simpleSyntaxHighlight = (code: string) => {
  if (!code) return '';
  let html = code
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  const tokens = [
    { regex: /(\/\/.*)/g, color: '#6a9955' }, // Comments
    { regex: /('.*?'|".*?"|`.*?`)/g, color: '#ce9178' }, // Strings
    { regex: /\b(import|export|from|const|let|var|function|return|if|else|for|while|async|await|default|class|interface|type|extends|implements|new|try|catch|finally)\b/g, color: '#c586c0' }, // Keywords
    { regex: /\b(true|false|null|undefined)\b/g, color: '#569cd6' }, // Primitives
    { regex: /\b(console|window|document|localStorage|sessionStorage|React|ReactDOM|useState|useEffect|useRef|useMemo)\b/g, color: '#4ec9b0' }, // Built-ins
    { regex: /(=&gt;|=>)/g, color: '#569cd6' }, // Arrows
    { regex: /({|}|\[|\]|\(|\))/g, color: '#ffd700' }, // Brackets
    { regex: /(&lt;\/?)(\w+)(.*?&gt;)/g, color: '#569cd6' }, // Tags
  ];

  const placeholders: string[] = [];
  tokens.forEach(token => {
      html = html.replace(token.regex, (match) => {
          if (token.color === '#569cd6' && match.startsWith('&lt;')) {
             return match.replace(/(&lt;\/?)([\w\.]+)(.*?&gt;)/g, (m, p1, p2, p3) => {
                 const tag = `<span style="color: #569cd6">${p1}${p2}</span>`;
                 const rest = p3;
                 placeholders.push(tag + rest);
                 return `___PLACEHOLDER_${placeholders.length - 1}___`;
             });
          }
          placeholders.push(`<span style="color: ${token.color}">${match}</span>`);
          return `___PLACEHOLDER_${placeholders.length - 1}___`;
      });
  });

  placeholders.forEach((ph, i) => {
      html = html.replace(`___PLACEHOLDER_${i}___`, ph);
  });

  return html;
};

export const ComponentInspector = ({ 
  isDevMode, 
  name, 
  concepts, 
  codeSnippet,
  children, 
  onInspect 
}: { 
  isDevMode: boolean, 
  name: string, 
  concepts: string[], 
  codeSnippet?: string,
  children: React.ReactNode, 
  onInspect: (data: InspectData) => void 
}) => {
  if (!isDevMode) return <>{children}</>;

  return (
    <div className="relative group rounded-[2.5rem] transition-all hover:ring-4 hover:ring-purple-500 cursor-help" onClick={(e) => {
      e.stopPropagation();
      onInspect({ name, concepts, codeSnippet });
    }}>
      <div className="absolute -top-3 left-4 z-50 bg-purple-600 text-white text-[9px] font-black uppercase px-2 py-1 rounded hidden group-hover:block animate-in fade-in slide-in-from-bottom-2 shadow-lg">
         Inspect: {name}
      </div>
      {children}
    </div>
  );
};

export const LessonOverlay = ({ content, onClose }: { content: LessonContent, onClose: () => void }) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(content.codeSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="fixed top-24 right-4 z-[999] w-full max-w-md animate-in slide-in-from-right fade-in duration-500">
       <div className="glass-bright p-6 rounded-[2rem] border border-purple-500/30 shadow-2xl relative bg-[#0f172a]/95">
          <button onClick={onClose} className="absolute top-4 right-4 w-8 h-8 bg-white/5 rounded-full flex items-center justify-center text-slate-400 hover:text-white transition-all"><i className="fas fa-times"></i></button>
          <div className="flex items-center gap-3 mb-4">
             <div className="w-10 h-10 rounded-xl bg-purple-600 flex items-center justify-center text-white shadow-lg animate-pulse"><i className="fas fa-chalkboard-user"></i></div>
             <div><h3 className="text-lg font-black italic text-white uppercase">{content.title}</h3><p className="text-[10px] font-bold text-purple-400 uppercase tracking-widest">Live Lesson</p></div>
          </div>
          <div className="prose prose-invert prose-sm mb-4"><p className="text-xs text-slate-300 font-medium leading-relaxed">{content.explanation}</p></div>
          <div className="relative group">
             <div className="absolute -top-3 right-2 px-2 py-1 bg-purple-600 text-white text-[8px] font-black uppercase rounded-md shadow-md z-10">TypeScript</div>
             <pre className="bg-[#020617] p-4 rounded-xl border border-white/10 overflow-x-auto text-[10px] font-mono text-purple-200 shadow-inner"><code>{content.codeSnippet}</code></pre>
             <button onClick={handleCopy} className="absolute top-2 right-2 p-2 bg-white/10 hover:bg-white/20 rounded-lg text-white transition-all"><i className={`fas ${copied ? 'fa-check text-emerald-400' : 'fa-copy'}`}></i></button>
          </div>
       </div>
    </div>
  );
};

// --- SIMULATED NETWORK STATE ---
const MOCK_NETWORK = [
    {
        ip: '192.168.1.25',
        os: 'Linux (Cloudflare WAF)',
        icon: 'fa-shield-halved',
        role: 'Protected Web App',
        openPorts: [
            { port: 80, service: 'http', version: 'Cloudflare' },
            { port: 443, service: 'https', version: 'Cloudflare' }
        ],
        vulnerabilities: [
            { type: 'Origin IP Leak', severity: 'High', description: 'Real server IP exposed via DNS history.', patched: false }
        ]
    },
    {
        ip: '192.168.1.30',
        os: 'Debian 10 (Buster)',
        icon: 'fa-server',
        role: 'Legacy File Server',
        openPorts: [
            { port: 21, service: 'ftp', version: 'vsftpd 3.0.3' }
        ],
        vulnerabilities: [
            { type: 'Anonymous Auth', severity: 'Medium', description: 'Anonymous login allowed on FTP.', patched: false }
        ]
    },
    {
        ip: '192.168.1.50',
        os: 'Android 13 (Techno Pop 8)',
        icon: 'fa-mobile-screen',
        role: 'Intern Device',
        openPorts: [
            { port: 5555, service: 'adb', version: 'Android Debug Bridge' },
            { port: 8080, service: 'http', version: 'XShare Transfer' }
        ],
        vulnerabilities: [
            { type: 'Unauth ADB', severity: 'Critical', description: 'Debug port exposed. Full shell access.', patched: false }
        ]
    },
    {
        ip: '192.168.1.55',
        os: 'iOS 17.4 (iPhone 15 Pro)',
        icon: 'fa-apple',
        role: 'CEO Mobile',
        openPorts: [
            { port: 62078, service: 'tcp', version: 'lockdownd' }
        ],
        vulnerabilities: [
            { type: 'Misconfigured Profile', severity: 'Medium', description: 'Development Provisioning Profile installed.', patched: false }
        ]
    },
    {
        ip: '192.168.1.60',
        os: 'Android 14 (Samsung S24)',
        icon: 'fa-mobile',
        role: 'Dev Device',
        openPorts: [
            { port: 5555, service: 'adb', version: 'Android Debug Bridge' },
            { port: 8000, service: 'http', version: 'Python SimpleHTTP' }
        ],
        vulnerabilities: [
            { type: 'Exposed Dev Server', severity: 'Medium', description: 'Source code exposed on port 8000.', patched: false }
        ]
    },
    {
        ip: '192.168.1.105',
        os: 'Ubuntu 20.04 LTS',
        icon: 'fa-linux',
        role: 'Legacy Web Server',
        openPorts: [
            { port: 80, service: 'http', version: 'Apache 2.4.41' },
            { port: 22, service: 'ssh', version: 'OpenSSH 8.2p1' },
            { port: 3306, service: 'mysql', version: 'MySQL 8.0.28' }
        ],
        vulnerabilities: [
            { type: 'SQL Injection', severity: 'Critical', description: 'Unsanitized input in /login endpoint allows Auth Bypass.', patched: false }
        ]
    },
    {
        ip: '192.168.1.110',
        os: 'Windows Server 2019',
        icon: 'fa-windows',
        role: 'Domain Controller',
        openPorts: [
            { port: 445, service: 'microsoft-ds', version: 'Windows Server 2019 Standard 17763' },
            { port: 3389, service: 'ms-wbt-server', version: 'RDP' }
        ],
        vulnerabilities: [
            { type: 'EternalBlue (MS17-010)', severity: 'Critical', description: 'Remote Code Execution via SMBv1 buffer overflow.', patched: false }
        ]
    },
    {
        ip: '192.168.1.220',
        os: 'Vercel / Supabase Edge',
        icon: 'fa-bolt',
        role: 'SaaS Backend',
        openPorts: [
            { port: 443, service: 'https', version: 'Vercel Edge' },
            { port: 5432, service: 'postgresql', version: 'Supabase Transaction Pooler' }
        ],
        vulnerabilities: [
            { type: 'RLS Misconfiguration', severity: 'Critical', description: 'Public access enabled on \'users\' table via Anon Key.', patched: false },
            { type: 'Exposed Env', severity: 'High', description: 'SUPABASE_SERVICE_ROLE_KEY leak in client bundle.', patched: false }
        ]
    },
    {
        ip: '192.168.1.210',
        os: 'Vercel / AWS Lambda',
        icon: 'fa-cloud',
        role: 'Modern SaaS (Next.js)',
        openPorts: [
            { port: 443, service: 'https', version: 'Next.js Server' }
        ],
        vulnerabilities: [
            { type: 'GraphQL Introspection', severity: 'Medium', description: 'Full schema exposed via /api/graphql.', patched: false }
        ]
    }
];

const SECURITY_TOOLS: SecurityTool[] = [
    {
        id: 'masscan',
        name: 'Masscan',
        category: 'Recon',
        description: 'Mass IP port scanner. Scans entire subnets in seconds.',
        command: 'masscan 192.168.1.0/24 -p21,80,443,445,5432,5555,62078',
        icon: 'fa-globe',
        concept: 'Masscan uses an asynchronous transmission mechanism, allowing it to scan the entire Internet in under 6 minutes. It is much faster than Nmap for discovery.'
    },
    {
        id: 'nmap',
        name: 'Nmap',
        category: 'Recon',
        description: 'Network Mapper for port scanning and OS detection.',
        command: 'nmap -sS -sV -A 192.168.1.220',
        icon: 'fa-network-wired',
        concept: 'Port Scanning involves sending packets to specific ports on a host. By analyzing the response (SYN/ACK), we determine if services are running.'
    },
    {
        id: 'wafw00f',
        name: 'Wafw00f',
        category: 'Web',
        description: 'Identifies and fingerprints Web Application Firewalls (WAF).',
        command: 'wafw00f https://192.168.1.25',
        icon: 'fa-shield-cat',
        concept: 'WAF Detection checks headers (e.g., cf-ray) and response behavior to identify if a site is protected by Cloudflare, AWS WAF, etc.'
    },
    {
        id: 'ftp',
        name: 'FTP Client',
        category: 'Exploitation',
        description: 'Standard File Transfer Protocol client.',
        command: 'ftp 192.168.1.30',
        icon: 'fa-folder-tree',
        concept: 'File Transfer Protocol (FTP) often suffers from weak credentials or anonymous access misconfigurations, allowing unauthorized file access.'
    },
    {
        id: 'wget',
        name: 'Wget',
        category: 'Web',
        description: 'Non-interactive network downloader.',
        command: 'wget http://192.168.1.220/index.html',
        icon: 'fa-download',
        concept: 'Wget is a command-line utility for downloading files from the web. It supports HTTP, HTTPS, and FTP protocols.'
    },
    {
        id: 'gobuster',
        name: 'Gobuster',
        category: 'Web',
        description: 'Directory/File, DNS and VHost busting tool written in Go.',
        command: 'gobuster dir -u http://192.168.1.220 -w common.txt',
        icon: 'fa-folder-open',
        concept: 'Directory Brute Forcing involves guessing hidden paths on a web server (like /.env, /admin, /backup) that are not linked on the main page.'
    },
    {
        id: 'eternalblue',
        name: 'EternalBlue',
        category: 'Exploitation',
        description: 'SMB Exploit (MS17-010) leaking from NSA. Targets Windows.',
        command: 'use exploit/windows/smb/ms17_010_eternalblue',
        icon: 'fa-windows',
        concept: 'EternalBlue exploits a vulnerability in Microsoft\'s Server Message Block (SMB) protocol. It allows remote code execution without authentication, notoriously used by WannaCry.'
    },
    {
        id: 'adb',
        name: 'ADB / Drozer',
        category: 'Exploitation',
        description: 'Android Debug Bridge & Security Assessment Framework.',
        command: 'adb connect 192.168.1.50:5555',
        icon: 'fa-android',
        concept: 'Android Debug Bridge (ADB) allows direct interaction with the filesystem. If left exposed on port 5555, attackers can install APKs, steal databases, or gain shell access.'
    },
    {
        id: 'metasploit',
        name: 'Metasploit',
        category: 'Exploitation',
        description: 'Penetration testing framework for developing and executing exploit code.',
        command: 'msfconsole',
        icon: 'fa-bomb',
        concept: 'Exploitation Frameworks standardize the process of delivering payloads (like reverse shells) to vulnerable systems. "meterpreter" is a popular dynamic payload.'
    },
    {
        id: 'hydra',
        name: 'Hydra',
        category: 'Cracking',
        description: 'Parallelized login cracker for multiple protocols.',
        command: 'hydra -l admin -P rockyou.txt ssh://192.168.1.105',
        icon: 'fa-dragon',
        concept: 'Brute Force attacks attempt every possible password combination. Dictionary attacks use a list of common passwords to speed this up.'
    },
    {
        id: 'wireshark',
        name: 'Wireshark',
        category: 'Sniffing',
        description: 'Network protocol analyzer for packet inspection.',
        command: 'tshark -i eth0',
        icon: 'fa-wave-square',
        concept: 'Packet Sniffing captures data flowing over a network. Unencrypted protocols (HTTP, Telnet) expose credentials in plain text.'
    },
    {
        id: 'john',
        name: 'John the Ripper',
        category: 'Cracking',
        description: 'Fast password cracker for offline hash cracking.',
        command: 'john --format=sha512crypt /etc/shadow',
        icon: 'fa-mask',
        concept: 'Hash Cracking involves computing hashes of candidate passwords and comparing them to the stolen hash. It works because hashes are deterministic.'
    },
    {
        id: 'burpsuite',
        name: 'Burp Suite',
        category: 'Web',
        description: 'Web vulnerability scanner and interception proxy.',
        command: 'burpsuite --intercept',
        icon: 'fa-bug-slash',
        concept: 'Interception Proxies sit between the browser and the server. They allow hackers to modify HTTP requests on the fly (e.g., changing price=100 to price=1) before they reach the server.'
    },
    {
        id: 'airgeddon',
        name: 'Airgeddon',
        category: 'Wireless',
        description: 'Multi-use bash script for wireless auditing and WPA/WPA2 cracking.',
        command: 'sudo bash airgeddon.sh',
        icon: 'fa-radiation',
        concept: 'A comprehensive suite that automates monitor mode enabling, handshake capturing, and various Evil Twin attacks (with or without captive portals).'
    },
    {
        id: 'wifite',
        name: 'Wifite2',
        category: 'Wireless',
        description: 'Automated wireless auditor. Attacks WEP, WPA, and WPS networks.',
        command: 'wifite --kill',
        icon: 'fa-satellite-dish',
        concept: 'Wireless auditing puts the card in "Monitor Mode". It performs de-authentication attacks to disconnect users and capture the WPA handshake for offline cracking.'
    }
];

const VULNERABLE_CODE_SNIPPET = `
// VULNERABLE CODE (Backend)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // ❌ DANGEROUS: Direct string concatenation
    // If password is "' OR '1'='1", the query becomes always true!
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    
    const user = await db.execute(query);
    if (user) {
        req.session.userId = user.id; // Login Successful
        res.send("Welcome, Admin!");
    }
});
`;

export const KaliTerminal = ({ 
    onClose, 
    terminalLogs, 
    onInput, 
    aiContext,
    missionSteps
}: { 
    onClose: () => void, 
    terminalLogs: TerminalLog[], 
    onInput: (cmd: string) => void,
    aiContext?: string,
    missionSteps?: KillChainStep[]
}) => {
    const [inputValue, setInputValue] = useState('');
    const [activeTab, setActiveTab] = useState<'network' | 'arsenal' | 'mission'>('network');
    const [selectedTool, setSelectedTool] = useState<SecurityTool | null>(null);
    const [selectedTarget, setSelectedTarget] = useState<any>(null);
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const [showExploit, setShowExploit] = useState(false);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [terminalLogs]);

    useEffect(() => {
        const lastLog = terminalLogs[terminalLogs.length - 1];
        if (lastLog && (lastLog.content.includes("Vulnerability Exposed") || lastLog.content.includes("Injection found") || lastLog.content.includes("Exploit Success") || lastLog.content.includes("Sensitive Data Exposure"))) {
            setTimeout(() => setShowExploit(true), 2000);
        }
    }, [terminalLogs]);

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter') {
            if (inputValue.trim()) {
                onInput(inputValue);
            }
            setInputValue('');
        }
    };

    const runTool = () => {
        if (selectedTool) {
            onInput(selectedTool.command);
        }
    };

    const renderTargetUI = () => {
        if (!selectedTarget) return null;

        // Windows Server UI
        if (selectedTarget.os.includes('Windows')) {
            return (
                <div className="bg-[#008080] w-full h-full relative font-sans select-none overflow-hidden rounded-r-xl">
                    <div className="absolute top-4 left-4 w-32">
                        <div className="flex flex-col items-center gap-1">
                           <i className="fas fa-recycle text-white text-2xl drop-shadow-md"></i>
                           <span className="text-white text-[10px] drop-shadow-md">Recycle Bin</span>
                        </div>
                    </div>
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 bg-[#c0c0c0] border-2 border-white border-b-black border-r-black shadow-xl">
                        <div className="bg-[#000080] text-white px-2 py-1 flex justify-between items-center text-xs font-bold bg-gradient-to-r from-[#000080] to-[#1084d0]">
                           <span>Server Manager</span>
                           <button className="bg-[#c0c0c0] text-black px-1 border border-white border-b-black border-r-black leading-none">X</button>
                        </div>
                        <div className="p-4 text-black text-[10px] font-mono leading-tight bg-black text-slate-300">
                           Microsoft Windows [Version 10.0]<br/>
                           (c) 2019 Microsoft Corp.<br/><br/>
                           C:\Users\Admin> <span className="animate-pulse">_</span>
                        </div>
                    </div>
                    <div className="absolute bottom-0 w-full h-8 bg-[#c0c0c0] border-t-2 border-white flex items-center px-2">
                        <button className="flex items-center gap-1 px-2 py-1 border-2 border-white border-b-black border-r-black bg-[#c0c0c0] active:border-b-white active:border-r-white active:border-t-black active:border-l-black">
                           <i className="fab fa-windows italic font-black"></i> <span className="font-bold text-xs">Start</span>
                        </button>
                        <div className="ml-auto border border-gray-500 bg-[#c0c0c0] px-2 text-xs shadow-inner">12:04 PM</div>
                    </div>
                </div>
            );
        }

        // Android / iOS UI
        if (selectedTarget.os.includes('Android') || selectedTarget.os.includes('iOS')) {
            const isIOS = selectedTarget.os.includes('iOS');
            return (
                <div className="w-full h-full bg-[#1a1a1a] flex justify-center items-center p-4 rounded-r-xl">
                    <div className={`w-[180px] h-[350px] ${isIOS ? 'bg-slate-800 rounded-[3rem]' : 'bg-black rounded-[2rem]'} border-4 border-slate-700 relative overflow-hidden shadow-2xl`}>
                        <div className="absolute top-0 w-full h-6 bg-black/50 flex justify-between px-3 items-center text-[8px] text-white z-20">
                           <span>12:42</span>
                           <div className="flex gap-1"><i className="fas fa-wifi"></i> <i className="fas fa-battery-full"></i></div>
                        </div>
                        <div className={`w-full h-full flex flex-col items-center justify-center ${isIOS ? 'bg-gradient-to-b from-blue-400 to-blue-200' : 'bg-gradient-to-br from-purple-900 to-indigo-900'}`}>
                            <div className="grid grid-cols-4 gap-4 p-4">
                                {[...Array(12)].map((_, i) => (
                                    <div key={i} className={`w-8 h-8 rounded-lg ${isIOS ? 'bg-white shadow-sm' : 'bg-white/20'}`}></div>
                                ))}
                            </div>
                        </div>
                        <div className="absolute bottom-4 w-full flex justify-around text-white text-xl z-20">
                           {isIOS ? (
                               <div className="w-24 h-1 bg-white rounded-full opacity-80"></div>
                           ) : (
                               <>
                                <i className="fas fa-bars text-xs"></i>
                                <i className="fas fa-square text-xs"></i>
                                <i className="fas fa-chevron-left text-xs"></i>
                               </>
                           )}
                        </div>
                        {/* Vulnerability Indicator */}
                        {selectedTarget.vulnerabilities.some((v: any) => v.severity === 'Critical') && (
                            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-black/80 p-4 rounded-xl text-center border border-red-500 animate-pulse w-3/4">
                               <i className="fas fa-bug text-red-500 text-2xl mb-2"></i>
                               <p className="text-red-500 text-[8px] font-black uppercase">Critical Exploit Available</p>
                            </div>
                        )}
                    </div>
                </div>
            );
        }

        // Web / Cloudflare / Vercel UI
        return (
            <div className="w-full h-full bg-slate-200 flex flex-col font-sans rounded-r-xl overflow-hidden">
               <div className="h-8 bg-slate-100 border-b border-slate-300 flex items-center px-2 gap-2">
                  <div className="flex gap-1"><div className="w-2 h-2 rounded-full bg-red-400"></div><div className="w-2 h-2 rounded-full bg-amber-400"></div><div className="w-2 h-2 rounded-full bg-emerald-400"></div></div>
                  <div className="flex-1 bg-white border border-slate-300 rounded-md h-5 text-[8px] flex items-center px-2 text-slate-500 shadow-sm truncate">
                      {selectedTarget.ip === '192.168.1.30' ? 'ftp://192.168.1.30' : `https://${selectedTarget.ip === '192.168.1.220' ? 'nexryde-app.vercel.app' : 'internal-dashboard.local'}`}
                  </div>
               </div>
               <div className="flex-1 p-4 bg-white overflow-y-auto">
                  {selectedTarget.ip === '192.168.1.30' ? (
                      <div className="font-mono text-xs">
                          <div className="border-b pb-1 mb-2 font-bold">Index of /</div>
                          <div className="flex items-center gap-2 py-1"><i className="fas fa-folder text-yellow-500"></i> ..</div>
                          <div className="flex items-center gap-2 py-1"><i className="fas fa-file text-slate-500"></i> backup_creds.txt</div>
                          <div className="flex items-center gap-2 py-1"><i className="fas fa-file-image text-slate-500"></i> logo.png</div>
                      </div>
                  ) : (
                      <>
                          <h1 className="text-xl font-black text-slate-800 mb-2">NexRyde</h1>
                          <div className="p-4 bg-slate-50 rounded-xl shadow-sm border border-slate-100">
                             <p className="text-xs text-slate-500 mb-2">Login to Dashboard</p>
                             <input disabled className="w-full bg-white border border-slate-200 p-2 rounded mb-2 text-xs" placeholder="Email" />
                             <input disabled className="w-full bg-white border border-slate-200 p-2 rounded mb-2 text-xs" placeholder="Password" />
                             <button className="w-full bg-black text-white py-2 rounded text-xs font-bold">Sign In</button>
                          </div>
                          {selectedTarget.ip === '192.168.1.220' && (
                              <div className="mt-4 p-2 bg-yellow-50 border border-yellow-200 rounded text-[8px] text-yellow-700 font-mono">
                                 DEBUG: SUPABASE_KEY exposed in console.
                              </div>
                          )}
                      </>
                  )}
               </div>
            </div>
        );
    };

    return (
        <div className="fixed inset-0 z-[1000] bg-[#0d0d0d] font-mono text-sm flex flex-col md:flex-row animate-in zoom-in duration-300">
            {/* Sidebar */}
            <div className="w-full md:w-64 bg-[#141414] border-r border-[#333] flex flex-col shrink-0">
                <div className="flex border-b border-[#333]">
                    <button onClick={() => setActiveTab('network')} className={`flex-1 py-3 text-[10px] font-black uppercase tracking-widest ${activeTab === 'network' ? 'bg-[#1f1f1f] text-emerald-500 border-b-2 border-emerald-500' : 'text-gray-500 hover:text-white'}`}>Network</button>
                    <button onClick={() => setActiveTab('arsenal')} className={`flex-1 py-3 text-[10px] font-black uppercase tracking-widest ${activeTab === 'arsenal' ? 'bg-[#1f1f1f] text-rose-500 border-b-2 border-rose-500' : 'text-gray-500 hover:text-white'}`}>Arsenal</button>
                    {missionSteps && <button onClick={() => setActiveTab('mission')} className={`flex-1 py-3 text-[10px] font-black uppercase tracking-widest ${activeTab === 'mission' ? 'bg-[#1f1f1f] text-blue-500 border-b-2 border-blue-500' : 'text-gray-500 hover:text-white'}`}>Mission</button>}
                </div>

                <div className="flex-1 overflow-y-auto p-4">
                    {activeTab === 'network' && (
                        <div className="space-y-2">
                            {MOCK_NETWORK.map((host) => (
                                <div key={host.ip} onClick={() => setSelectedTarget(host)} className={`p-3 rounded-lg border cursor-pointer transition-all ${selectedTarget?.ip === host.ip ? 'bg-emerald-900/20 border-emerald-500' : 'bg-black border-[#333] hover:border-gray-500'}`}>
                                    <div className="flex items-center gap-2">
                                        <i className={`fab ${host.icon} ${selectedTarget?.ip === host.ip ? 'text-emerald-500' : 'text-gray-500'}`}></i>
                                        <span className="text-xs font-bold text-white">{host.ip}</span>
                                    </div>
                                    <p className="text-[8px] text-gray-500 uppercase mt-1 pl-6">{host.role}</p>
                                </div>
                            ))}
                        </div>
                    )}
                    {activeTab === 'arsenal' && (
                        <div className="grid grid-cols-2 gap-2">
                            {SECURITY_TOOLS.map(tool => (
                                <div key={tool.id} onClick={() => setSelectedTool(tool)} className="p-2 bg-[#1f1f1f] border border-[#333] rounded-lg cursor-pointer hover:border-rose-500 hover:bg-[#252525]">
                                    <i className={`fas ${tool.icon} text-lg text-gray-500 mb-1`}></i>
                                    <p className="text-[9px] font-bold text-white">{tool.name}</p>
                                </div>
                            ))}
                        </div>
                    )}
                    {activeTab === 'mission' && missionSteps && (
                        <div className="space-y-2">
                            {missionSteps.map(step => (
                                <div key={step.id} className={`p-3 rounded-lg border ${step.status === 'active' ? 'bg-blue-900/20 border-blue-500' : 'bg-transparent border-[#333] opacity-50'}`}>
                                    <p className="text-[9px] font-black uppercase text-blue-400">{step.name}</p>
                                    <p className="text-[8px] text-gray-300 mt-1">{step.objective}</p>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* Main Content Area: Split Terminal and Target UI */}
            <div className="flex-1 flex">
                <div className={`flex flex-col relative border-r border-[#333] bg-black ${selectedTarget ? 'w-2/3' : 'w-full'}`}>
                    {/* Terminal Top Bar */}
                    <div className="h-8 bg-[#1f1f1f] flex items-center justify-between px-4 select-none border-b border-[#333]">
                        <div className="flex gap-2 items-center">
                            <i className="fab fa-linux text-white"></i>
                            <span className="text-xs font-bold text-gray-300">root@kali: ~</span>
                        </div>
                        <button onClick={onClose} className="text-xs text-gray-400 hover:text-white"><i className="fas fa-times"></i></button>
                    </div>
                    {/* Terminal Output */}
                    <div className="flex-1 p-4 overflow-y-auto font-mono text-sm">
                        <div className="text-gray-400 mb-4">
                            <p className="text-blue-400 font-bold">┌──(root㉿kali)-[~]</p>
                            <p className="text-white">└─# <span className="text-gray-400">./init_pentest_lab.sh</span></p>
                        </div>
                        {terminalLogs.map((log, i) => (
                            <div key={i} className="mb-1 whitespace-pre-wrap break-all">
                                {log.type === 'input' ? <><span className="text-blue-400 font-bold">root@kali:~#</span> <span className="text-white">{log.content}</span></> : 
                                 log.type === 'error' ? <span className="text-red-500">{log.content}</span> :
                                 log.type === 'success' ? <span className="text-emerald-400">{log.content}</span> :
                                 log.type === 'warning' ? <span className="text-amber-500">{log.content}</span> :
                                 <span className="text-gray-300">{log.content}</span>}
                            </div>
                        ))}
                        <div ref={messagesEndRef} />
                        {/* Prompt */}
                        <div className="flex items-center mt-2">
                            <span className="text-blue-400 font-bold mr-2">root@kali:~#</span>
                            <input value={inputValue} onChange={e => setInputValue(e.target.value)} onKeyDown={handleKeyDown} className="bg-transparent border-none outline-none text-white w-full font-mono" autoFocus />
                        </div>
                    </div>
                    {/* Exploit Overlay */}
                    {showExploit && (
                        <div className="absolute bottom-4 right-4 w-80 bg-[#0d0d0d] border border-red-500 rounded-xl shadow-2xl p-4 animate-in slide-in-from-right z-50">
                            <h4 className="text-red-500 font-bold uppercase text-xs mb-2"><i className="fas fa-bug"></i> Vulnerability Found</h4>
                            <pre className="bg-black p-2 rounded border border-white/10 text-[8px] text-gray-300 overflow-x-auto">{VULNERABLE_CODE_SNIPPET}</pre>
                            <button onClick={() => setShowExploit(false)} className="mt-2 text-[9px] text-gray-500 underline uppercase">Dismiss</button>
                        </div>
                    )}
                </div>

                {/* Target UI Preview */}
                {selectedTarget && (
                    <div className="w-1/3 bg-[#111] relative">
                        <div className="absolute top-2 right-2 z-10">
                            <button onClick={() => setSelectedTarget(null)} className="w-6 h-6 bg-black/50 rounded-full text-white flex items-center justify-center hover:bg-red-500 transition-colors"><i className="fas fa-times text-xs"></i></button>
                        </div>
                        {renderTargetUI()}
                        
                        {/* Target Info Overlay */}
                        <div className="absolute bottom-0 w-full bg-[#111]/90 border-t border-[#333] p-4">
                            <h3 className="text-white font-bold text-sm">{selectedTarget.ip}</h3>
                            <p className="text-[10px] text-gray-400 uppercase">{selectedTarget.os}</p>
                            <div className="mt-2 flex flex-wrap gap-1">
                                {selectedTarget.openPorts.map((p: any) => (
                                    <span key={p.port} className="px-2 py-0.5 bg-emerald-900/30 text-emerald-400 border border-emerald-500/30 rounded text-[9px] font-mono">{p.port}/{p.service}</span>
                                ))}
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export const VSCodeTutor = ({ 
    onClose, 
    onCodeUpdate, 
    externalCode,
    missionSteps 
}: { 
    onClose: () => void, 
    onCodeUpdate: (filename: string, code: string) => void,
    externalCode?: {filename: string, code: string} | null,
    missionSteps?: KillChainStep[] 
}) => {
    // Files include Full Stack NexRyde Implementation for learning
    const [files, setFiles] = useState<{name: string, language: string, content: string}[]>([
        { name: 'App.tsx', language: 'typescript', content: `import React from 'react';\nimport Garage from './Curriculum/01_Components';\n\nexport const App = () => {\n  return (\n    <div className="app">\n       <h1>NexRyde Learning</h1>\n       <Garage />\n    </div>\n  );\n};` },
        { name: 'vite.config.ts', language: 'typescript', content: `import { defineConfig } from 'vite';\nimport react from '@vitejs/plugin-react';\n\n// Vite is a build tool that aims to provide a faster and leaner development experience for modern web projects.\nexport default defineConfig({\n  plugins: [react()],\n  build: {\n    outDir: 'dist',\n  },\n});` },
        { name: 'vercel.json', language: 'json', content: `{\n  "rewrites": [\n    { "source": "/(.*)", "destination": "/index.html" }\n  ]\n}` },
        { name: 'package.json', language: 'json', content: `{\n  "name": "nexryde-app",\n  "scripts": {\n    "dev": "vite",\n    "build": "vite build",\n    "preview": "vite preview"\n  },\n  "dependencies": {\n    "react": "^19.0.0",\n    "@google/genai": "^1.38.0",\n    "@supabase/supabase-js": "^2.48.1"\n  }\n}` },
        { name: 'lib/ai.ts', language: 'typescript', content: `import { GoogleGenAI } from "@google/genai";\n\n// Initialize Gemini API Client\nconst apiKey = process.env.API_KEY;\nexport const ai = new GoogleGenAI({ apiKey });\n\n// Configuration for Voice Assistant\nexport const VOICE_CONFIG = {\n  model: "gemini-2.5-flash-native-audio-preview-12-2025",\n  voice: "Kore"\n};` },
        { name: 'components/QRCode.tsx', language: 'typescript', content: `import React from 'react';\n\n// Generates a visual QR Code for ride verification\nexport const RideQR = ({ pin }: { pin: string }) => {\n  const url = \`https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=\${pin}\`;\n  return (\n    <div className="bg-white p-2 rounded-xl">\n       <img src={url} alt="Ride PIN" className="w-32 h-32" />\n       <p className="text-center font-bold text-black mt-2">{pin}</p>\n    </div>\n  );\n};` },
        { name: 'components/VoiceOrb.tsx', language: 'typescript', content: `import React, { useState } from 'react';\nimport { ai } from '../lib/ai';\n\n// Main AI Interface Component\nexport const VoiceOrb = () => {\n  const [active, setActive] = useState(false);\n\n  const toggle = async () => {\n     if(active) return;\n     setActive(true);\n     const session = await ai.live.connect({ model: 'gemini-2.5-flash' });\n     // ... audio stream logic ...\n  };\n\n  return <button onClick={toggle}>{active ? 'Listening...' : 'Speak'}</button>;\n};` },
        { name: 'backend/supabase.ts', language: 'typescript', content: `import { createClient } from '@supabase/supabase-js';\n\n// Database Connection\nconst SUPABASE_URL = "https://kzjgihwxiaeqzopeuzhm.supabase.co";\nconst SUPABASE_ANON_KEY = process.env.SUPABASE_KEY;\n\nexport const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);\n\n// Helper to fetch rides\nexport const getRides = async () => {\n  return await supabase.from('unihub_nodes').select('*');\n};` },
        { name: 'index.html', language: 'html', content: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NexRyde Vercel App</title>
</head>
<body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
    <!-- Captured from 192.168.1.220 -->
</body>
</html>` },
        { name: 'Curriculum/01_Components.tsx', language: 'typescript', content: `// 1. REACT COMPONENTS\n// Components are independent and reusable bits of code.\n// They serve the same purpose as JavaScript functions, but work in isolation and return HTML.\n\nfunction Car() {\n  return <h2>Hi, I am a Car!</h2>;\n}\n\nexport default function Garage() {\n  return (\n    <>\n      <h1>Who lives in my Garage?</h1>\n      <Car />\n    </>\n  );\n}` },
        { name: 'global.css', language: 'css', content: `body {\n  background: #020617;\n  color: #fff;\n}` },
    ]);
    const [activeFile, setActiveFile] = useState(files[0]);
    const [activeSidebar, setActiveSidebar] = useState<'explorer' | 'mission'>('explorer');
    const [isRunning, setIsRunning] = useState(false);
    const [terminalLogs, setTerminalLogs] = useState<string[]>([
       "Microsoft Windows [Version 10.0.19045.4291]",
       "(c) Microsoft Corporation. All rights reserved.",
       "",
       "C:\\Users\\Student\\nexryde-app>_"
    ]);
    const [isTerminalOpen, setIsTerminalOpen] = useState(true);

    // Sync external code (AI generated)
    useEffect(() => {
        if(externalCode) {
            const ext = externalCode.filename.split('.').pop() || 'typescript';
            const lang = ext === 'json' ? 'json' : ext === 'html' ? 'html' : ext === 'css' ? 'css' : 'typescript';
            
            setFiles(prev => {
                const exists = prev.find(f => f.name === externalCode.filename);
                if (exists) {
                    return prev.map(f => f.name === externalCode.filename ? {...f, content: externalCode.code} : f);
                }
                return [...prev, { name: externalCode.filename, language: lang, content: externalCode.code }];
            });
            setActiveFile({ name: externalCode.filename, language: lang, content: externalCode.code });
        }
    }, [externalCode]);

    const handleCodeChange = (newCode: string) => {
        setActiveFile(prev => ({...prev, content: newCode}));
        setFiles(prev => prev.map(f => f.name === activeFile.name ? {...f, content: newCode} : f));
        onCodeUpdate(activeFile.name, newCode);
    };

    const handleRun = () => {
        setIsRunning(true);
        setIsTerminalOpen(true);
        setTimeout(() => {
             let output: string[] = [
                `> npm start ${activeFile.name}`,
                "Starting development server...",
                "Local:   http://localhost:5173/",
                "Network: http://192.168.1.10:5173/",
                `[HMR] connected.`
             ];
             setTerminalLogs(prev => [...prev, ...output, "", "C:\\Users\\Student\\nexryde-app>_"]);
             setIsRunning(false);
        }, 1000);
    };

    // --- BROWSER PREVIEW COMPONENT ---
    const BrowserPreview = () => {
        const renderContent = () => {
            if (activeFile.name.includes('App.tsx')) {
                return (
                    <div className="p-4 flex flex-col items-center justify-center h-full text-center">
                        <div className="w-16 h-16 bg-gradient-to-tr from-amber-400 to-orange-500 rounded-2xl flex items-center justify-center shadow-lg mb-4">
                           <i className="fas fa-route text-white text-3xl"></i>
                        </div>
                        <h1 className="text-2xl font-black text-slate-800">NexRyde Learning</h1>
                        <p className="text-slate-500 text-sm mt-2">Welcome to your first React App!</p>
                        <div className="mt-6 p-4 bg-slate-100 rounded-xl w-full max-w-xs">
                            <h2 className="font-bold text-slate-700">Garage Component</h2>
                            <p className="text-xs text-slate-500">Who lives in my Garage?</p>
                            <div className="mt-2 px-3 py-1 bg-white rounded border text-xs font-bold text-slate-600 inline-block">Hi, I am a Car!</div>
                        </div>
                    </div>
                );
            }
            if (activeFile.name.includes('QRCode.tsx')) {
                return (
                    <div className="p-8 flex flex-col items-center justify-center h-full">
                        <div className="bg-white p-4 rounded-xl shadow-xl border border-slate-100">
                            <img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=1234" alt="QR" className="w-32 h-32 mix-blend-multiply" />
                            <p className="text-center font-bold text-slate-800 mt-2 text-lg tracking-widest">1234</p>
                        </div>
                        <p className="mt-4 text-xs text-slate-400 uppercase font-bold">Ride Verification PIN</p>
                    </div>
                );
            }
            if (activeFile.name.includes('VoiceOrb.tsx') || activeFile.name.includes('ai.ts')) {
                return (
                    <div className="flex flex-col items-center justify-center h-full bg-black">
                        <div className="w-24 h-24 rounded-full bg-gradient-to-tr from-indigo-600 to-purple-600 flex items-center justify-center shadow-2xl shadow-purple-500/50 animate-pulse">
                            <i className="fas fa-microphone text-white text-3xl"></i>
                        </div>
                        <p className="mt-8 text-white font-black italic uppercase tracking-widest">Listening...</p>
                        <div className="flex gap-1 mt-4 h-4 items-end">
                            <div className="w-1 h-4 bg-indigo-500 animate-bounce"></div>
                            <div className="w-1 h-8 bg-purple-500 animate-bounce delay-75"></div>
                            <div className="w-1 h-6 bg-indigo-500 animate-bounce delay-150"></div>
                            <div className="w-1 h-3 bg-purple-500 animate-bounce delay-100"></div>
                        </div>
                    </div>
                );
            }
            if (activeFile.name.includes('index.html')) {
                return (
                    <div className="w-full h-full bg-white p-4 font-sans text-slate-800">
                        <h1 className="text-2xl font-bold">NexRyde Vercel App</h1>
                        <p className="mt-2 text-sm text-slate-600">This is the raw HTML entry point.</p>
                        <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded text-xs text-yellow-800 font-mono">
                            {`<!-- WARNING: EXPOSED ENV VARS DETECTED -->`}
                        </div>
                    </div>
                );
            }
            return (
                <div className="flex flex-col items-center justify-center h-full text-slate-400">
                    <i className="fas fa-laptop-code text-4xl mb-4 opacity-50"></i>
                    <p className="text-xs font-bold uppercase">Ready to compile</p>
                </div>
            );
        };

        return (
            <div className="flex flex-col h-full bg-white border-l border-[#333] shadow-2xl relative">
                <div className="h-8 bg-slate-100 border-b border-slate-200 flex items-center px-2 justify-between">
                    <div className="flex items-center gap-2 w-full">
                        <div className="flex gap-1">
                            <div className="w-2 h-2 rounded-full bg-slate-300"></div>
                            <div className="w-2 h-2 rounded-full bg-slate-300"></div>
                        </div>
                        <div className="flex-1 bg-white h-5 rounded border border-slate-200 flex items-center px-2 text-[9px] text-slate-500 truncate">
                            http://localhost:5173/{activeFile.name.replace('.tsx','').replace('.ts','').toLowerCase()}
                        </div>
                        <i className="fas fa-rotate-right text-slate-400 text-xs hover:text-slate-600 cursor-pointer"></i>
                    </div>
                </div>
                <div className="flex-1 overflow-auto bg-slate-50 relative">
                    {renderContent()}
                </div>
                <div className="absolute bottom-0 right-0 p-2 opacity-50 pointer-events-none">
                    <i className="fas fa-eye text-slate-300 text-6xl"></i>
                </div>
            </div>
        );
    };

    return (
        <div className="fixed inset-0 z-[2000] bg-[#1e1e1e] flex text-[#cccccc] font-mono text-sm animate-in zoom-in duration-300 select-none">
            {/* Sidebar (Explorer/Mission) - Same as before */}
            <div className="w-12 bg-[#333333] flex flex-col items-center py-4 gap-6 border-r border-[#252526] z-20 shrink-0">
                <i className={`fas fa-copy text-2xl cursor-pointer transition-colors ${activeSidebar === 'explorer' ? 'text-white border-l-2 border-white pl-2' : 'text-[#858585] hover:text-white'}`} onClick={() => setActiveSidebar('explorer')} title="Explorer"></i>
                <i className={`fas fa-graduation-cap text-2xl cursor-pointer transition-colors ${activeSidebar === 'mission' ? 'text-white border-l-2 border-white pl-2' : 'text-[#858585] hover:text-white'}`} onClick={() => setActiveSidebar('mission')} title="Mission Control"></i>
                <div className="flex-1"></div>
                <i className="fas fa-cog text-2xl text-[#858585] hover:text-white cursor-pointer"></i>
            </div>

            <div className="w-64 bg-[#252526] flex flex-col border-r border-[#1e1e1e] shrink-0">
                <div className="h-10 px-4 flex items-center justify-between text-[11px] font-bold text-[#bbbbbb] uppercase tracking-wider bg-[#252526]">
                    <span>{activeSidebar === 'explorer' ? 'Explorer' : 'Mission Control'}</span>
                </div>
                <div className="flex-1 overflow-y-auto">
                    {activeSidebar === 'explorer' ? (
                        <>
                            <div className="px-2 py-1 text-[11px] font-bold text-blue-400 flex items-center gap-1 cursor-pointer">
                                <i className="fas fa-chevron-down text-[8px]"></i> <span>NEXRYDE-CLIENT</span>
                            </div>
                            <div className="mt-1">
                                {files.map(file => (
                                    <div key={file.name} onClick={() => setActiveFile(file)} className={`pl-6 pr-4 py-1 cursor-pointer flex items-center gap-2 hover:bg-[#2a2d2e] transition-colors ${activeFile.name === file.name ? 'bg-[#37373d] text-white' : 'text-[#cccccc]'}`}>
                                        <i className={`fas ${file.language === 'css' ? 'fa-hashtag text-blue-300' : file.language === 'json' ? 'fa-code text-yellow-300' : file.language === 'html' ? 'fa-html5 text-orange-500' : 'fa-file-code text-yellow-500'} text-xs w-4 text-center`}></i>
                                        <span>{file.name}</span>
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : (
                        <div className="p-2 space-y-3">
                             {missionSteps?.map(step => (
                                 <div key={step.id} className={`p-3 rounded-md border ${step.status === 'active' ? 'bg-[#37373d] border-blue-500' : step.status === 'completed' ? 'bg-[#2d2d2d] border-emerald-500/30 opacity-70' : 'bg-[#2d2d2d] border-transparent opacity-50'}`}>
                                     <div className="flex justify-between items-center mb-1">
                                         <span className={`text-[10px] font-bold uppercase ${step.status === 'active' ? 'text-blue-400' : step.status === 'completed' ? 'text-emerald-400' : 'text-gray-500'}`}>{step.name}</span>
                                         {step.status === 'completed' && <i className="fas fa-check text-emerald-400 text-xs"></i>}
                                     </div>
                                     <p className="text-[10px] text-gray-300 mb-2 leading-tight">{step.objective}</p>
                                 </div>
                             ))}
                        </div>
                    )}
                </div>
            </div>

            {/* Split View: Editor (Left) & Browser (Right) */}
            <div className="flex-1 flex overflow-hidden">
                {/* EDITOR COLUMN */}
                <div className="flex-1 flex flex-col min-w-[300px] border-r border-[#333]">
                    {/* Tabs */}
                    <div className="flex bg-[#252526] overflow-x-auto border-b border-[#1e1e1e] h-9 no-scrollbar pr-20 relative shrink-0">
                        {files.map(file => (
                            <div key={file.name} onClick={() => setActiveFile(file)} className={`px-3 flex items-center gap-2 text-xs min-w-[120px] max-w-[200px] cursor-pointer border-r border-[#1e1e1e] group ${activeFile.name === file.name ? 'bg-[#1e1e1e] text-white border-t-2 border-t-blue-500' : 'bg-[#2d2d2d] text-[#969696] hover:bg-[#252526]'}`}>
                                 <i className={`fas ${file.language === 'css' ? 'fa-hashtag text-blue-300' : file.language === 'json' ? 'fa-code text-yellow-300' : file.language === 'html' ? 'fa-html5 text-orange-500' : 'fa-file-code text-yellow-500'} text-xs`}></i>
                                 <span className="truncate">{file.name}</span>
                            </div>
                        ))}
                        <div className="absolute right-0 top-0 h-full flex items-center pr-2 bg-[#252526] pl-4">
                            <button onClick={handleRun} className="flex items-center gap-2 px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-[10px] font-bold uppercase transition-colors">
                                <i className={`fas ${isRunning ? 'fa-spinner fa-spin' : 'fa-play'}`}></i>
                            </button>
                        </div>
                    </div>

                    {/* Breadcrumbs */}
                    <div className="h-6 flex items-center px-4 text-[11px] text-[#969696] gap-2 border-b border-[#2b2b2b] bg-[#1e1e1e] shrink-0">
                        <span>src</span>
                        <i className="fas fa-chevron-right text-[8px]"></i>
                        <span className="text-white">{activeFile.name}</span>
                    </div>

                    {/* Code Editor */}
                    <div className="flex-1 relative overflow-hidden flex">
                        <div className="w-12 text-right pr-4 pt-4 text-[#858585] select-none text-xs leading-6 bg-[#1e1e1e] shrink-0">
                            {activeFile.content.split('\n').map((_, i) => <div key={i}>{i + 1}</div>)}
                        </div>
                        <div className="flex-1 relative font-mono text-sm leading-6 custom-scrollbar overflow-auto">
                             <div className="absolute top-0 left-0 min-w-full min-h-full p-4 pointer-events-none whitespace-pre" dangerouslySetInnerHTML={{ __html: simpleSyntaxHighlight(activeFile.content) }}></div>
                             <textarea value={activeFile.content} onChange={(e) => handleCodeChange(e.target.value)} className="absolute top-0 left-0 min-w-full min-h-full bg-transparent text-transparent caret-white p-4 outline-none resize-none whitespace-pre font-mono text-sm leading-6 z-10" spellCheck={false} />
                        </div>
                    </div>

                    {/* Terminal Panel */}
                    <div className={`border-t border-[#333] bg-[#1e1e1e] flex flex-col transition-all ${isTerminalOpen ? 'h-36' : 'h-6'} shrink-0`}>
                        <div className="flex items-center px-4 h-6 bg-[#252526] gap-4 text-[10px] uppercase font-bold text-[#bbbbbb] cursor-pointer" onClick={() => setIsTerminalOpen(!isTerminalOpen)}>
                            <div className="flex items-center gap-1 border-b border-white text-white h-full px-2"><i className="fas fa-terminal"></i> Terminal</div>
                            <div className="ml-auto hover:text-white"><i className={`fas ${isTerminalOpen ? 'fa-chevron-down' : 'fa-chevron-up'}`}></i></div>
                        </div>
                        {isTerminalOpen && (
                            <div className="flex-1 p-2 font-mono text-xs text-[#cccccc] overflow-y-auto bg-black">
                                {terminalLogs.map((log, i) => <div key={i} className="mb-1">{log}</div>)}
                            </div>
                        )}
                    </div>
                </div>

                {/* BROWSER COLUMN */}
                <div className="w-[40%] min-w-[250px] h-full">
                    <BrowserPreview />
                </div>
            </div>

            {/* Close Button */}
            <button onClick={onClose} className="absolute top-2 right-[41%] z-50 bg-[#333] hover:bg-[#444] text-white w-8 h-8 flex items-center justify-center rounded shadow-xl border border-[#444]"><i className="fas fa-times"></i></button>

            {/* Status Bar */}
            <div className="h-6 bg-[#007acc] flex items-center justify-between px-3 text-[11px] text-white select-none absolute bottom-0 w-full z-[60]">
                <div className="flex gap-4"><span className="flex items-center gap-1"><i className="fas fa-code-branch"></i> main*</span></div>
                <div className="flex gap-4"><span>Ln {activeFile.content.split('\n').length}, Col 1</span><span>UTF-8</span><span>TypeScript React</span></div>
            </div>
        </div>
    );
};

export const DevPanel = ({ 
    activeComponent, 
    onClose, 
    onAskAi, 
    onLaunchTutor 
}: { 
    activeComponent: InspectData | null, 
    onClose: () => void, 
    onAskAi: () => void, 
    onLaunchTutor: () => void 
}) => {
    if (!activeComponent) return null;
    return (
        <div className="fixed bottom-24 right-4 z-[900] w-80 bg-[#0f172a]/90 backdrop-blur-xl border border-purple-500/30 p-6 rounded-2xl shadow-2xl animate-in slide-in-from-right fade-in">
             <div className="flex justify-between items-start mb-4">
                 <h3 className="text-lg font-black text-white italic">{activeComponent.name}</h3>
                 <button onClick={onClose} className="text-slate-400 hover:text-white"><i className="fas fa-times"></i></button>
             </div>
             <div className="flex flex-wrap gap-2 mb-4">
                 {activeComponent.concepts.map((c, i) => (
                     <span key={i} className="px-2 py-1 bg-purple-500/20 text-purple-300 rounded text-[9px] font-bold uppercase">{c}</span>
                 ))}
             </div>
             <div className="flex gap-2">
                 <button onClick={onAskAi} className="flex-1 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-bold transition-all">Explain AI</button>
                 <button onClick={onLaunchTutor} className="flex-1 py-2 bg-white/10 hover:bg-white/20 text-white rounded-lg text-xs font-bold transition-all">View Code</button>
             </div>
        </div>
    );
};

export const DevModeFloat = ({ 
    isDevMode, 
    onToggle, 
    onLaunchTutor, 
    onLaunchSecurity 
}: { 
    isDevMode: boolean, 
    onToggle: () => void, 
    onLaunchTutor: () => void, 
    onLaunchSecurity: () => void 
}) => {
    return (
        <div className="fixed top-20 right-4 z-[900] flex flex-col items-end gap-2">
            <button 
                onClick={onToggle} 
                className={`px-4 py-2 rounded-full font-black text-[9px] uppercase tracking-widest shadow-xl transition-all flex items-center gap-2 ${isDevMode ? 'bg-purple-600 text-white' : 'bg-black/50 backdrop-blur text-slate-400 hover:text-white border border-white/10'}`}
            >
                <i className="fas fa-code"></i> {isDevMode ? 'Dev Mode ON' : 'Dev Mode OFF'}
            </button>
            {isDevMode && (
                <div className="flex flex-col gap-2 animate-in slide-in-from-top-2 fade-in">
                    <button onClick={onLaunchTutor} className="w-10 h-10 rounded-full bg-[#1e1e1e] border border-white/20 text-blue-400 shadow-xl flex items-center justify-center hover:scale-110 transition-transform" title="Code Tutor">
                        <i className="fas fa-laptop-code"></i>
                    </button>
                    <button onClick={onLaunchSecurity} className="w-10 h-10 rounded-full bg-[#0d0d0d] border border-emerald-500/30 text-emerald-500 shadow-xl flex items-center justify-center hover:scale-110 transition-transform" title="Kali Linux Sandbox">
                        <i className="fas fa-terminal"></i>
                    </button>
                </div>
            )}
        </div>
    );
};
