
export type VehicleType = 'Pragia' | 'Taxi' | 'Shuttle';
export type NodeStatus = 'forming' | 'qualified' | 'dispatched' | 'completed'; 
export type PortalMode = 'passenger' | 'driver' | 'admin' | 'public' | 'learning' | 'security';

export interface SearchConfig {
  query: string;
  vehicleType: VehicleType | 'All';
  status: NodeStatus | 'All';
  sortBy: 'newest' | 'price' | 'capacity';
  isSolo: boolean | null;
}

export interface UniUser {
  id: string;
  username: string;
  phone: string;
  pin?: string;
}

export interface Passenger {
  id: string;
  name: string;
  phone: string;
  verificationCode?: string;
}

export interface HubMission {
  id: string;
  location: string;
  description: string;
  entryFee: number;
  driversJoined: string[]; // List of driver IDs
  status: 'open' | 'closed';
  createdAt: string;
}

export interface RideNode {
  id: string;
  destination: string;
  origin: string;
  capacityNeeded: number;
  passengers: Passenger[];
  status: NodeStatus;
  leaderName: string;
  leaderPhone: string;
  farePerPerson: number;
  createdAt: string;
  assignedDriverId?: string;
  verificationCode?: string;
  isSolo?: boolean;
  isLongDistance?: boolean;
  negotiatedTotalFare?: number;
  vehicleType?: VehicleType; 
  driverNote?: string;
}

export interface Driver {
  id: string;
  name: string;
  vehicleType: VehicleType;
  licensePlate: string;
  contact: string;
  walletBalance: number; 
  rating: number;
  status: 'online' | 'busy' | 'offline';
  pin: string; 
  avatarUrl?: string; 
}

export interface TopupRequest {
  id: string;
  driverId: string;
  amount: number;
  momoReference: string;
  status: 'pending' | 'approved' | 'rejected';
  timestamp: string;
}

export interface RegistrationRequest {
  id: string;
  name: string;
  vehicleType: VehicleType;
  licensePlate: string;
  contact: string;
  pin: string;
  amount: number;
  momoReference: string;
  status: 'pending' | 'approved' | 'rejected';
  timestamp: string;
  avatarUrl?: string; 
}

export interface Transaction {
  id: string;
  driverId: string;
  amount: number;
  type: 'commission' | 'topup' | 'registration'; 
  timestamp: string;
}

export interface AppSettings {
  id?: number;
  adminMomo: string;
  adminMomoName: string;
  whatsappNumber: string;
  commissionPerSeat: number;
  adminSecret?: string;
  farePerPragia: number;
  farePerTaxi: number;
  soloMultiplier: number;
  aboutMeText: string;
  aboutMeImages: string[]; // Base64 strings
  appWallpaper?: string; // Base64 string
  appLogo?: string; // Base64 string for custom logo
  registrationFee: number;
  hub_announcement?: string;
  // Social Media Config
  facebookUrl?: string;
  instagramUrl?: string;
  tiktokUrl?: string;
  // AdSense Config
  adSenseClientId?: string;
  adSenseSlotId?: string;
  adSenseLayoutKey?: string; // Optional for in-feed
  adSenseStatus?: 'active' | 'inactive';
}

export interface LessonContent {
  title: string;
  explanation: string; // Markdown supported
  codeSnippet: string;
}

export interface InspectData {
  name: string;
  concepts: string[];
  codeSnippet?: string;
}

export interface CodeContext {
  filename: string;
  code: string;
}

// --- SECURITY TYPES ---
export interface TerminalLog {
  type: 'input' | 'output' | 'error' | 'success' | 'info' | 'warning';
  content: string;
  timestamp: string;
}

export interface SecurityTarget {
  ip: string;
  os: string;
  openPorts: { port: number, service: string, version: string }[];
  vulnerabilities: { type: string, severity: 'Low' | 'Medium' | 'High' | 'Critical', description: string, patched: boolean }[];
}

export interface SecurityTool {
  id: string;
  name: string;
  category: 'Recon' | 'Web' | 'Exploitation' | 'Cracking' | 'Sniffing' | 'Social Engineering' | 'Phishing' | 'Wireless';
  description: string;
  command: string;
  icon: string;
  concept: string; // Educational explanation
}

export interface KillChainStep {
  id: number;
  name: string;
  status: 'locked' | 'active' | 'completed';
  objective: string;
  hint: string;
  requiredTool: string;
}
