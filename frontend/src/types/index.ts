export type UserRole = "USER" | "ADMIN";

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export type RiskClassification =
  | "SAFE"
  | "SUSPICIOUS"
  | "HIGH RISK"
  | "CRITICAL";
export type SeverityLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type DetectionSource =
  | "RULE"
  | "ML"
  | "VISION"
  | "NLP"
  | "CANARY"
  | "THREAT_INTEL"
  | "DSA_SECURITY_ENGINE"
  | string;
export type LayerId = "L1" | "L2" | "L3" | "L4" | "L5" | "L6" | string;

export interface DetectionReason {
  id?: string;
  rule_id?: string;
  title?: string;
  reason: string;
  severity: SeverityLevel;
  source: DetectionSource;
  layer?: LayerId;
  weight?: number;
}

export interface LayerFinding {
  rule_id: string;
  title: string;
  reason: string;
  severity: SeverityLevel;
  weight: number;
  source: DetectionSource;
  layer: LayerId;
}

export interface LayerResultData {
  layer_id: LayerId;
  layer_name: string;
  executed: boolean;
  skipped_reason?: string | null;
  score: number;
  findings_count: number;
  findings: LayerFinding[];
  metadata: Record<string, any>;
  duration_ms: number;
}

export interface RedirectHop {
  url: string;
  status: number | string;
  hop: number;
  redirect_to?: string;
  server?: string;
  error?: string;
}

export interface ExtractedFeatures {
  url_length: number;
  domain_length: number;
  path_length: number;
  query_length: number;
  num_dots: number;
  num_hyphens: number;
  num_underscores: number;
  num_slashes: number;
  num_question_marks: number;
  num_equals: number;
  num_at_symbols: number;
  num_percent: number;
  num_ampersands: number;
  num_digits: number;
  num_subdomains: number;
  has_ip_address: number;
  is_https: number;
  has_suspicious_tld: number;
  has_typosquatting?: number;
  has_brand_keyword: number;
  has_punycode: number;
  is_shortened: number;
  domain_entropy: number;
  dns_resolvable?: number | boolean;
  resolved_ip?: string | null;
  ssl_valid?: number | boolean;
  ssl_version?: string | null;
  ssl_issuer?: string | null;
  ssl_days_left?: number | null;
  ssl_error?: string | null;
  http_status?: number | null;
  final_url?: string | null;
  is_redirected?: number | boolean;
  is_cross_domain_redirect?: number | boolean;
  has_hsts?: number | boolean;
  has_x_frame_options?: number | boolean;
  has_csp?: number | boolean;
  has_x_content_type_options?: number | boolean;
  server_banner?: string | null;
  page_title?: string | null;
  detected_brands?: string[];
  detected_tld?: string;
  hostname?: string;
  // Layer 1 extended
  typosquat_distance?: number;
  domain_age_days?: number | null;
  threat_feed_hits?: number;
  decoded_hostname?: string;
  is_government_domain?: number;
  government_entity?: string;
  is_authentic_brand?: number;
  authentic_brand_name?: string;
  // Layer 3 extended
  form_count?: number;
  cross_origin_forms?: number;
  has_password_input?: number;
  has_credential_harvest?: number;
  js_obfuscation_score?: number;
  // Layer 4 extended
  urgency_keyword_count?: number;
  has_payment_flags?: number;
  vision_similarity_score?: number;
  // Layer 2 extended
  redirect_depth?: number;
}

export interface ScanResult {
  id: string;
  user_id?: string;
  input_type: string;
  input_value: string;
  risk_score: number;
  classification: RiskClassification;
  ml_probability: number;
  model_version: string;
  recommendation?: string;
  created_at: string;
  detection_reasons: DetectionReason[];
  features?: ExtractedFeatures;
  // 6-Layer Pipeline
  layer_results?: LayerResultData[];
  redirect_chain?: RedirectHop[];
  screenshot_url?: string;
  scan_duration_ms?: number;
  layers_executed?: string;
}

export interface PaginatedScans {
  items: ScanResult[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface DashboardSummary {
  total_scans: number;
  safe_scans: number;
  suspicious_scans: number;
  high_risk_scans: number;
  critical_scans: number;
  average_risk_score: number;
  threat_detection_rate: number;
  recent_scans: ScanResult[];
  risk_distribution: {
    SAFE: number;
    SUSPICIOUS: number;
    HIGH_RISK: number;
    CRITICAL: number;
  };
}

export interface AuditLog {
  id: string;
  user_id?: string;
  user_email?: string;
  action: string;
  ip_address?: string;
  details?: string;
  created_at: string;
}

export interface AdminStats {
  total_users: number;
  active_users: number;
  total_system_scans: number;
  threats_prevented: number;
  model_version: string;
  system_health: string;
  model_metrics?: {
    test_accuracy?: number;
    test_precision?: number;
    test_recall?: number;
    test_f1?: number;
    test_roc_auc?: number;
    confusion_matrix?: number[][];
  };
}
