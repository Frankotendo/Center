import { GoogleGenAI, Modality, Type } from "@google/genai";
import { Mission, Target, SimulationResponse, TargetType, Lecture, LectureStep } from '../types';

// Initialize Gemini Client Lazily
// Note: In Vite/Vercel, ensure your API key is exposed via environment variables.
const getAI = () => new GoogleGenAI({ apiKey: process.env.API_KEY || '' });

// Helper to strip Markdown formatting and extra text from JSON responses
const cleanJSON = (text: string): string => {
  if (!text) return "{}";
  
  // First, remove markdown code blocks
  let cleaned = text.replace(/```json\n?|```/g, '');
  
  // Find the first '{' or '[' and the last '}' or ']'
  const firstBrace = cleaned.indexOf('{');
  const lastBrace = cleaned.lastIndexOf('}');
  const firstBracket = cleaned.indexOf('[');
  const lastBracket = cleaned.lastIndexOf(']');
  
  // Determine if we are looking for an object or array
  let start = -1;
  let end = -1;

  if (firstBrace !== -1 && (firstBracket === -1 || firstBrace < firstBracket)) {
      start = firstBrace;
      end = lastBrace;
  } else if (firstBracket !== -1) {
      start = firstBracket;
      end = lastBracket;
  }

  if (start !== -1 && end !== -1) {
      cleaned = cleaned.substring(start, end + 1);
  }
  
  return cleaned.trim();
};

// --- Simulation Logic (Game Master) ---

export const executeCommand = async (
  command: string,
  mission: Mission,
  target: Target,
  historySummary: string
): Promise<SimulationResponse> => {
  const model = 'gemini-3-flash-preview'; 

  const prompt = `
    ACT AS: "Kore", a military-grade Cyber Warfare Training AI.
    CONTEXT: The user is an operative in a high-fidelity Red Team simulator (Kali Linux environment).
    
    MISSION INTEL:
    - Operation: ${mission.title}
    - Objective: ${mission.description}
    - Target Type: ${target.type}
    - Target OS: ${target.os}
    - Target Details: ${JSON.stringify(target)}
    
    CONSOLE HISTORY (Last 5 lines):
    ${historySummary}
    
    USER INPUT: "${command}"
    
    TASK: Generate a simulation response in JSON.
    
    GUIDELINES:
    1. 'terminalOutput': MUST be highly realistic CLI output.
       - If Target is **iPhone/iOS**: Simulate 'jailbroken' file structures (/var/mobile), output from tools like 'cycript' or 'ssh' into an iOS shell.
       - If Target is **Android**: Simulate ADB shell output, logcat snippets, or package listings (com.android...).
       - If Target is **Database (Supabase/Postgres)**: Show realistic psql connection outputs, SQL syntax errors, or table dumps.
       - If Target is **WiFi**: Show 'airmon-ng' monitor mode status, 'airodump-ng' BSSID lists with signal strength (PWR).
       - If Target is **IoT**: Show RTSP stream connection logs or embedded Linux shell (BusyBox) outputs.
       - For 'nmap', ensure ports match the target type (e.g., 5432 for DB, 5555 for ADB, 22 for SSH, 80/443 for Web).
    2. 'instructorCommentary': Short, tactical voiceover. Teach the user *why* the command worked or failed. If they are stuck, guide them.
    3. 'missionUpdate': Mark completed ONLY if the specific objective logic is satisfied by the command's success.
    4. 'targetUpdate': If a scan (nmap) or exploit reveals new info (open ports, vulns), update this field.
    
    CRITICAL: NO REAL MALICIOUS ACTIONS. SIMULATION ONLY.
  `;

  try {
    const ai = getAI();
    const response = await ai.models.generateContent({
      model,
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            terminalOutput: { type: Type.STRING },
            instructorCommentary: { type: Type.STRING },
            missionUpdate: {
              type: Type.OBJECT,
              properties: {
                status: { type: Type.STRING, enum: ['ongoing', 'completed', 'failed'] },
                progressLog: { type: Type.STRING }
              }
            },
            targetUpdate: {
              type: Type.OBJECT,
              properties: {
                ports: { type: Type.ARRAY, items: { type: Type.INTEGER } },
                vulnerabilities: { type: Type.ARRAY, items: { type: Type.STRING } },
                status: { type: Type.STRING, enum: ['online', 'compromised', 'offline'] }
              }
            }
          }
        }
      }
    });

    const text = response.text;
    if (!text) throw new Error("No response from simulation engine");
    
    return JSON.parse(cleanJSON(text)) as SimulationResponse;
  } catch (error) {
    console.error("Simulation Error:", error);
    return {
      terminalOutput: `[SYSTEM ERROR] Uplink instability detected.\n${error}`,
      instructorCommentary: "Connection unstable. Re-establish uplink and retry.",
      missionUpdate: { status: 'ongoing' }
    };
  }
};

// --- Text to Speech (Voice) ---

export const generateSpeech = async (text: string): Promise<ArrayBuffer | null> => {
  if (!text || text.trim().length === 0) return null;

  try {
    const ai = getAI();
    // Truncate to safe length (approx 4000 chars) to prevent backend timeouts
    const safeText = text.slice(0, 4000); 

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash-preview-tts",
      contents: [{ parts: [{ text: safeText }] }],
      config: {
        // Use string literal "AUDIO" cast to any to ensure browser compatibility with the SDK enum
        responseModalities: ["AUDIO" as any], 
        speechConfig: {
          voiceConfig: {
            prebuiltVoiceConfig: { voiceName: 'Kore' },
          },
        },
      },
    });

    const base64Audio = response.candidates?.[0]?.content?.parts?.[0]?.inlineData?.data;
    if (!base64Audio) {
        // This is a valid case (e.g. model decided not to speak), but rare for TTS
        return null;
    }

    // Decode Base64 to ArrayBuffer
    const binaryString = atob(base64Audio);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (error: any) {
    // Handle specific XHR/Network errors gracefully without crashing the flow
    if (error?.message?.includes('500') || error?.message?.includes('xhr error')) {
        console.warn("TTS System Offline (Network/API Error): Voice synthesis skipped.");
    } else {
        console.error("TTS generation failed:", error);
    }
    return null;
  }
};

// --- Mission Generation ---

export const generateNewMissions = async (completedCount: number): Promise<Mission[]> => {
    // Determine difficulty based on completed count
    const level = completedCount < 5 ? 'Beginner' : completedCount < 15 ? 'Intermediate' : 'Advanced';
    
    const prompt = `Generate 3 unique cybersecurity training missions for a student at ${level} level.
    The targets should vary (Web, Mobile, Cloud, IoT).
    Return a JSON array of Mission objects.
    Each mission needs a unique ID, title, brief description, list of objectives, recommended tools (e.g. nmap, wireshark, burpsuite), and a briefing script for the instructor.
    Also generate a mocked 'targetId' for each (e.g., 'target-001').`;

    try {
        const ai = getAI();
        const response = await ai.models.generateContent({
            model: "gemini-3-flash-preview",
            contents: prompt,
            config: {
                responseMimeType: "application/json",
                responseSchema: {
                    type: Type.ARRAY,
                    items: {
                        type: Type.OBJECT,
                        properties: {
                            id: { type: Type.STRING },
                            title: { type: Type.STRING },
                            difficulty: { type: Type.STRING },
                            description: { type: Type.STRING },
                            objectives: { type: Type.ARRAY, items: { type: Type.STRING } },
                            targetId: { type: Type.STRING },
                            completed: { type: Type.BOOLEAN },
                            recommendedTools: { type: Type.ARRAY, items: { type: Type.STRING } },
                            briefing: { type: Type.STRING }
                        }
                    }
                }
            }
        });
        
        return JSON.parse(cleanJSON(response.text || "[]"));
    } catch (e) {
        console.error("Mission Gen Error", e);
        return [];
    }
}

// --- Target Generation ---
export const generateTarget = async (targetId: string, typeHint: string): Promise<Target> => {
    const prompt = `Generate a detailed simulated target profile for a cybersecurity mission.
    ID: ${targetId}
    Type Hint: ${typeHint} (e.g. Supabase DB, iPhone 14, Vercel App).
    Return JSON.`;

    try {
       const ai = getAI();
       const response = await ai.models.generateContent({
           model: "gemini-3-flash-preview",
           contents: prompt,
           config: {
               responseMimeType: "application/json",
               responseSchema: {
                   type: Type.OBJECT,
                   properties: {
                       id: {type: Type.STRING},
                       name: {type: Type.STRING},
                       type: {type: Type.STRING}, // Enum mapping handled by caller logic if needed, simple string here is fine for sim
                       ip: {type: Type.STRING},
                       os: {type: Type.STRING},
                       vulnerabilities: {type: Type.ARRAY, items: {type: Type.STRING}},
                       ports: {type: Type.ARRAY, items: {type: Type.INTEGER}},
                       status: {type: Type.STRING},
                       description: {type: Type.STRING}
                   }
               }
           }
       });
       const data = JSON.parse(cleanJSON(response.text || "{}"));
       // Ensure defaults
       return {
           ...data,
           vulnerabilities: [], // Start hidden
           ports: [], // Start hidden
           status: 'online'
       } as Target;
    } catch (e) {
        return {
            id: targetId,
            name: "Unknown Target",
            type: TargetType.SERVER,
            ip: "10.10.10.10",
            os: "Linux",
            vulnerabilities: [],
            ports: [],
            status: 'online',
            description: "A mysterious server."
        };
    }
}

// --- Lecture Generation (Whiteboard Tutor) ---
export const generateLecture = async (topic: string): Promise<Lecture> => {
    const prompt = `
        ACT AS: A senior cybersecurity professor ("Professor Cypher").
        TASK: Create a deep-dive educational lecture on the topic: "${topic}".
        STRUCTURE: Break the explanation into 3-5 distinct steps.
        
        For each step, provide:
        1. 'voiceScript': The verbal explanation. Be deep, technical, but clear. Explain the 'why' and 'how'.
        2. 'boardNotes': Bullet points, diagrams (ASCII), or code snippets that would be written on a whiteboard. Use Markdown for code.
        
        The first step should be an introduction. The last step should be a summary or a call to action to practice.
    `;

    try {
        const ai = getAI();
        const response = await ai.models.generateContent({
            model: "gemini-3-flash-preview",
            contents: prompt,
            config: {
                responseMimeType: "application/json",
                responseSchema: {
                    type: Type.OBJECT,
                    properties: {
                        steps: {
                            type: Type.ARRAY,
                            items: {
                                type: Type.OBJECT,
                                properties: {
                                    voiceScript: { type: Type.STRING },
                                    boardNotes: { type: Type.STRING }
                                }
                            }
                        }
                    }
                }
            }
        });

        const data = JSON.parse(cleanJSON(response.text || "{}"));
        return {
            topic,
            steps: data.steps || [],
            currentStepIndex: 0
        };
    } catch (e) {
        console.error("Lecture Gen Error", e);
        return {
            topic: "Error",
            steps: [{ voiceScript: "I cannot access the curriculum database at this moment.", boardNotes: "SYSTEM ERROR: CURRICULUM UNAVAILABLE" }],
            currentStepIndex: 0
        };
    }
}