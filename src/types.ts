export type TabId = 'email' | 'sender' | 'url' | 'gmail';

export interface EmailAttachmentInput {
  filename: string;
  mime_type?: string;
  content_base64: string;
  size?: number;
}

export interface AttachmentAnalysisResult {
  filename: string;
  file_size?: number;
  formatted_size?: string;
  classification: string;
  risk_score: number;
  detected_signals?: string[];
}

export interface HeaderAnalysisResult {
  hasAuthenticationResults?: boolean;
  spf?: string;
  dkim?: string;
  dmarc?: string;
}

export interface UrlAnalysisItem {
  url: string;
  diagnostics?: {
    threat_probability?: number;
    classification?: string;
    flags?: string[];
    features?: any;
    reasoning?: string;
  };
}

export interface EmailAnalysisResult {
  classification: 'Phishing' | 'Suspicious' | 'Legitimate' | string;
  risk_score: number;
  risk_level?: string;
  probability?: number;
  confidence_label?: string;
  reasoning?: string;
  detected_signals?: string[];
  top_email_text_features?: Record<string, number>;
  sender_analysis?: {
    sender_email?: string;
    domain?: string;
    risk_score?: number;
    features?: {
      brandImpersonationFound?: boolean;
      hasLookalike?: boolean;
      isTrusted?: boolean;
      [key: string]: any;
    };
    [key: string]: any;
  };
  header_analysis?: HeaderAnalysisResult;
  url_analysis?: UrlAnalysisItem[];
  attachment_analysis?: AttachmentAnalysisResult[];
  ai_analysis?: AiThreatAnalysis;
}

export interface AiThreatAnalysis {
  threat_level: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';
  threat_score: number;
  confidence: 'High' | 'Medium' | 'Low';
  attack_intent: string;
  summary: string;
  social_engineering_tactics: Array<{
    tactic: string;
    severity: 'High' | 'Medium' | 'Low';
    explanation: string;
  }>;
  contextual_reasoning: string;
  key_indicators: string[];
  recommended_mitigation: string[];
}

export interface SenderAnalysisResult {
  sender_email: string;
  classification: 'Phishing' | 'Suspicious' | 'Legitimate' | string;
  risk_score: number;
  confidence?: number;
  reasoning?: string;
  detected_signals?: string[];
  parsed_structure?: {
    displayName?: string;
    domain?: string;
    tld?: string;
    localPart?: string;
  };
  heuristic_flags?: {
    brand_impersonation?: boolean;
    homoglyph_or_typo?: boolean;
    is_suspicious_tld?: boolean;
    is_disposable_domain?: boolean;
    [key: string]: any;
  };
}

export interface UrlAnalysisResult {
  url: string;
  classification: 'Phishing' | 'Suspicious' | 'Legitimate' | string;
  risk_score: number;
  reasoning?: string;
  ml_probability?: number;
  model_version?: string;
  top_url_features?: Record<string, number>;
  diagnostics?: {
    threat_probability?: number;
    classification?: string;
    flags?: string[];
    features?: any;
  };
}

export interface InboxEmail {
  id: string;
  from: string;
  senderName?: string;
  subject: string;
  date: string;
  snippet?: string;
  body?: string;
  isStarred?: boolean;
  isUnread?: boolean;
  classification: 'Phishing' | 'Suspicious' | 'Legitimate' | string;
  risk_score: number;
  detected_features?: string[];
  attachments?: AttachmentAnalysisResult[];
  attachment_analysis?: AttachmentAnalysisResult[];
}

export interface InboxStats {
  total: number;
  phishing: number;
  suspicious: number;
  legitimate: number;
}

declare global {
  interface Window {
    google?: {
      accounts?: {
        oauth2?: {
          initTokenClient: (config: {
            client_id: string;
            scope: string;
            callback: (response: {
              access_token?: string;
              error?: string;
              error_description?: string;
            }) => void;
          }) => {
            requestAccessToken: (options?: { prompt?: string }) => void;
          };
          revoke: (token: string, done: () => void) => void;
        };
      };
    };
  }
}
