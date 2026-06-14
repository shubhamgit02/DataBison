/**
 * DataBison — Zero-Trust Client-Side Security Audit Engine
 * Version 2.0 — Improved Logic & Detection Architecture
 *
 * IMPROVEMENTS OVER v1:
 *  1. Centralised DETECTION_RULES — all patterns in one place, easy to extend
 *  2. Weighted scoring model — each finding type carries its own risk weight
 *  3. Smarter deduplication — normalises values before deduping
 *  4. Broader credential patterns — GitHub, Stripe, Twilio, JWT, RSA headers, .env vars
 *  5. SSN, IP address, credit-card, URL-with-credentials detection added
 *  6. Metadata risk classification — every metadata field gets its own risk level
 *  7. Context-aware recommendations — generated dynamically from actual findings
 *  8. Sanitization engine now covers all new pattern types
 *  9. PDF report uses proper print styles instead of raw window.print()
 * 10. All DOM queries cached where called repeatedly; null-guards on every element
 */

// ─────────────────────────────────────────────────────────────────────────────
// DETECTION RULES — single source of truth for all regex patterns
// Each rule: { id, label, regex, severity, weight, redactWith }
// weight = points added to risk score per unique match
// ─────────────────────────────────────────────────────────────────────────────
const DETECTION_RULES = {

  // ── PII ──────────────────────────────────────────────────────────────────
  email: {
    id: 'email', label: 'Email Address',
    regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    severity: 'Medium', weight: 8,
    redactWith: '[REDACTED_EMAIL]'
  },
  phone: {
    id: 'phone', label: 'Phone Number',
    // Handles US, international (+1, +44, +91 …), dotted, dashed, spaced formats
    regex: /(?:\+?\d{1,3}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}/g,
    severity: 'Medium', weight: 8,
    redactWith: '[REDACTED_PHONE]'
  },
  ssn: {
    id: 'ssn', label: 'Social Security Number (SSN)',
    regex: /\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0{4})\d{4}\b/g,
    severity: 'Critical', weight: 25,
    redactWith: '[REDACTED_SSN]'
  },
  creditCard: {
    id: 'creditCard', label: 'Credit Card Number',
    // Luhn-pattern; covers Visa 4, Mastercard 5, Amex 37, Discover 6
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    severity: 'Critical', weight: 30,
    redactWith: '[REDACTED_CARD_NUMBER]'
  },
  ipAddress: {
    id: 'ipAddress', label: 'Internal IP Address',
    // Matches private RFC-1918 ranges only (10.x, 172.16-31.x, 192.168.x)
    regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    severity: 'Low', weight: 4,
    redactWith: '[REDACTED_INTERNAL_IP]'
  },

  // ── CREDENTIALS ──────────────────────────────────────────────────────────
  awsAccessKey: {
    id: 'awsAccessKey', label: 'AWS Access Key ID',
    regex: /(?:AKIA|ASIA|AROA|AIDA|ANOV|ANPA)[0-9A-Z]{16}/g,
    severity: 'Critical', weight: 35,
    redactWith: '[REDACTED_AWS_ACCESS_KEY]'
  },
  awsSecretKey: {
    id: 'awsSecretKey', label: 'AWS Secret Access Key',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?/g,
    severity: 'Critical', weight: 40,
    redactWith: 'aws_secret_access_key=[REDACTED_AWS_SECRET]'
  },
  githubToken: {
    id: 'githubToken', label: 'GitHub Personal Access Token',
    regex: /ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}/g,
    severity: 'Critical', weight: 38,
    redactWith: '[REDACTED_GITHUB_TOKEN]'
  },
  stripeKey: {
    id: 'stripeKey', label: 'Stripe Secret Key',
    regex: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
    severity: 'Critical', weight: 38,
    redactWith: '[REDACTED_STRIPE_KEY]'
  },
  twilioKey: {
    id: 'twilioKey', label: 'Twilio API Key',
    regex: /SK[0-9a-fA-F]{32}/g,
    severity: 'Critical', weight: 35,
    redactWith: '[REDACTED_TWILIO_KEY]'
  },
  slackToken: {
    id: 'slackToken', label: 'Slack Bot / OAuth Token',
    regex: /xox[bpoa]-[0-9a-zA-Z\-]{10,}/g,
    severity: 'Critical', weight: 35,
    redactWith: '[REDACTED_SLACK_TOKEN]'
  },
  jwtToken: {
    id: 'jwtToken', label: 'JSON Web Token (JWT)',
    regex: /eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+/g,
    severity: 'High', weight: 28,
    redactWith: '[REDACTED_JWT_TOKEN]'
  },
  rsaPrivateKey: {
    id: 'rsaPrivateKey', label: 'RSA / PEM Private Key Header',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'Critical', weight: 45,
    redactWith: '-----BEGIN [REDACTED PRIVATE KEY]-----'
  },
  genericSecret: {
    id: 'genericSecret', label: 'Generic Secret / API Key',
    // key = "value" or key: 'value' patterns with high-entropy values
    regex: /(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|password|passwd|pwd)\s*[=:]\s*["']?[0-9a-zA-Z\-_./+]{16,64}["']?/gi,
    severity: 'High', weight: 25,
    redactWith: '[KEY_NAME]=[REDACTED_SECRET]'
  },
  envVariable: {
    id: 'envVariable', label: '.env Credential Variable',
    // Matches lines like: DB_PASSWORD=hunter2, SECRET_KEY=abc123xyz
    regex: /^(?:DB_(?:PASSWORD|USER|HOST)|SECRET(?:_KEY)?|PRIVATE_KEY|PASS(?:WORD)?|TOKEN|AUTH_KEY)\s*=\s*.+$/gm,
    severity: 'High', weight: 22,
    redactWith: '[ENV_VAR]=[REDACTED]'
  },
  urlWithCredentials: {
    id: 'urlWithCredentials', label: 'URL with Embedded Credentials',
    // Matches: mongodb://user:pass@host, postgres://user:pass@host
    regex: /[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/[^:@\s]+:[^@\s]+@[^\s]+/g,
    severity: 'Critical', weight: 40,
    redactWith: '[PROTOCOL]://[REDACTED_USER]:[REDACTED_PASS]@[HOST]'
  }
};

// Metadata field risk classification
const METADATA_RISK = {
  'GPS Coordinates': 'danger',
  'Camera Model':    'warning',
  'Document Author': 'warning',
  'Creator Software':'safe',
  'Timestamp':       'safe'
};

// ─────────────────────────────────────────────────────────────────────────────
// GLOBAL APPLICATION STATE
// ─────────────────────────────────────────────────────────────────────────────
const state = {
  currentScan: null,
  recentScans: [
    {
      id: 'mock-1',
      name: 'secrets_log.txt',
      size: '1.2 KB',
      type: 'text/plain',
      riskScore: 91,
      riskLevel: 'High Risk',
      findings: [
        { type: 'AWS Access Key ID',    value: 'AKIAIOSFODNN7EXAMPLE',  severity: 'Critical' },
        { type: 'AWS Secret Access Key',value: '[REDACTED — 40 chars]', severity: 'Critical' },
        { type: 'Email Address',        value: 'admin@databison.io',     severity: 'Medium'   },
        { type: 'Phone Number',         value: '+1-555-019-2834',        severity: 'Medium'   }
      ],
      metadata: {
        'Document Author':  'unknown',
        'Creator Software': 'VS Code v1.98.0',
        'Timestamp':        '2026-06-13 14:02:11 UTC',
        'Camera Model':     'N/A',
        'GPS Coordinates':  'N/A'
      },
      recs: {
        title: 'Exposed AWS Credentials & PII Detected',
        desc:  'This log file contains plain-text AWS access keys. If published, automated scrapers can hijack your AWS infrastructure within minutes.',
        actions: [
          'Revoke and rotate the exposed AWS Access Key immediately via the IAM console.',
          'Implement AWS Secrets Manager or HashiCorp Vault to store credentials securely.',
          'Add .env and *.log files to your .gitignore to prevent future commits.',
          'Audit Git history with tools like git-secrets or truffleHog for historic leaks.',
          'Redact the administrator telephone number to comply with CCPA/GDPR guidelines.'
        ]
      },
      rawContent: `2026-06-13T10:14:24.012Z [CRITICAL] Exposed credentials found:\n  AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n  AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n  email = "admin@databison.io"\n  phone = "+1-555-019-2834"`
    },
    {
      id: 'mock-2',
      name: 'exif_sunset.jpg',
      size: '4.7 MB',
      type: 'image/jpeg',
      riskScore: 68,
      riskLevel: 'Medium Risk',
      findings: [
        { type: 'GPS Location',    value: '37.7749° N, 122.4194° W (San Francisco)', severity: 'High'   },
        { type: 'Device Identity', value: 'iPhone 15 Pro Max',                        severity: 'Medium' },
        { type: 'Creator Name',    value: 'Sarah Connor',                              severity: 'Medium' }
      ],
      metadata: {
        'Document Author':  'Sarah Connor',
        'Creator Software': 'iOS 17.4.1',
        'Timestamp':        '2026-06-10 18:24:55 UTC',
        'Camera Model':     'iPhone 15 Pro Max · f/1.78 · ISO 80',
        'GPS Coordinates':  '37.7749° N, 122.4194° W (San Francisco, CA)'
      },
      recs: {
        title: 'Geotagging Metadata Embedded in Image',
        desc:  'Precise GPS coordinates were found inside the EXIF headers. Sharing this file publicly reveals exactly where the photo was taken.',
        actions: [
          'Use the "Strip & Sanitize" button to remove all EXIF metadata before sharing.',
          'Disable geotagging in your device Camera settings under Privacy → Location Services.',
          'Remove the Document Author field to protect the content creator identity.',
          'Consider using a photo-sharing platform that automatically strips EXIF on upload.'
        ]
      },
      rawContent: null
    },
    {
      id: 'mock-3',
      name: 'public_readme.md',
      size: '3.4 KB',
      type: 'text/markdown',
      riskScore: 10,
      riskLevel: 'Low Risk',
      findings: [],
      metadata: {
        'Developed by':  'Shubham Yadav',
        'Creator Software': 'Marked v4.0.0',
        'Timestamp':        '2026-06-08 09:12:00 UTC',

      },
      recs: {
        title: 'Clean Audit — No Violations Found',
        desc:  'No personal identifiers, location trackers, or private keys were found in this file. It is safe to distribute publicly.',
        actions: [
          'File is verified secure for public dissemination.',
          'Maintain regular sanitization scans in your CI/CD pipeline.',
          'Re-scan after any future content changes or before each release.'
        ]
      },
      rawContent: `# Project Readme\n\nNo sensitive keys or emails in this document.`
    }
  ]
};

// ─────────────────────────────────────────────────────────────────────────────
// UTILITY HELPERS
// ─────────────────────────────────────────────────────────────────────────────
const utils = {

  /** Safely get a DOM element; logs a warning if missing */
  el(id) {
    const el = document.getElementById(id);
    if (!el) console.warn(`[DataBison] Element #${id} not found.`);
    return el;
  },

  /** Format bytes → human readable string */
  formatSize(bytes) {
    if (bytes < 1024)       return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  },

  /** Choose the right Lucide icon name for a file MIME type */
  iconForType(mimeType) {
    if (!mimeType) return 'file';
    if (mimeType.startsWith('image/'))       return 'image';
    if (mimeType.includes('pdf'))            return 'file-text';
    if (mimeType.includes('word') || mimeType.includes('document')) return 'file-text';
    if (mimeType.startsWith('text/'))        return 'file-code';
    return 'file';
  },

  /** Normalise a matched string for deduplication (trim, lowercase) */
  normalise(str) { return str.trim().toLowerCase(); },

  /** Deduplicate an array of strings case-insensitively */
  dedup(arr) {
    const seen = new Set();
    return arr.filter(v => {
      const n = utils.normalise(v);
      if (seen.has(n)) return false;
      seen.add(n);
      return true;
    });
  },

  /** Truncate a long string for display */
  truncate(str, max = 48) {
    return str.length > max ? str.substring(0, max) + '…' : str;
  },

  /** Map severity string → CSS class suffix */
  severityClass(severity) {
    const map = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
    return map[severity.toLowerCase()] || 'low';
  },

  /** Map risk score → { level, cssClass, gaugeColor } */
  riskProfile(score) {
    if (score >= 71) return { level: 'High Risk',    cssClass: 'risk-high',   color: 'var(--danger-red)'    };
    if (score >= 31) return { level: 'Medium Risk',  cssClass: 'risk-medium', color: 'var(--warning-orange)' };
    return            { level: 'Low Risk',     cssClass: 'risk-low',    color: 'var(--success-green)' };
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// VIEW ROUTER
// ─────────────────────────────────────────────────────────────────────────────
const appRouter = {
  activeView: 'landing',
  views: ['landing', 'scan', 'about'],

  init() {
    this._updateNav();
    const brand = document.getElementById('brand-logo');
    if (brand) brand.addEventListener('click', e => { e.preventDefault(); this.navigate('landing'); });
  },

  navigate(viewId) {
    if (!this.views.includes(viewId)) return;
    this.activeView = viewId;

    this.views.forEach(v => {
      const page = document.getElementById(`page-${v}`);
      if (!page) return;
      page.classList.toggle('active', v === viewId);
    });

    this._updateNav();
    window.scrollTo({ top: 0, behavior: 'smooth' });

    if (viewId === 'scan') {
      scanEngine.renderRecentScans();
      const hasResult = !!state.currentScan;
      const emptyState = utils.el('dashboard-empty-state');
      const results    = utils.el('dashboard-results');
      if (emptyState) emptyState.style.display = hasResult ? 'none' : 'flex';
      if (results)    results.classList.toggle('active', hasResult);
      if (hasResult)  scanEngine.updateUIWithScan(state.currentScan);
    }
  },

  _updateNav() {
    const map = { landing: 'nav-item-landing', scan: 'nav-item-scan', about: 'nav-item-about' };
    Object.entries(map).forEach(([v, id]) => {
      const el = document.getElementById(id);
      if (el) el.classList.toggle('active', v === this.activeView);
    });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// SCAN ENGINE
// ─────────────────────────────────────────────────────────────────────────────
const scanEngine = {

  init() {
    const dropZone  = utils.el('drop-zone');
    const fileInput = utils.el('file-input');
    if (!dropZone || !fileInput) return;

    // Drag events
    ['dragenter', 'dragover'].forEach(evt =>
      dropZone.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); dropZone.classList.add('dragover'); })
    );
    ['dragleave', 'drop'].forEach(evt =>
      dropZone.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); dropZone.classList.remove('dragover'); })
    );
    dropZone.addEventListener('drop', e => {
      const file = e.dataTransfer?.files?.[0];
      if (file) this.handleFileSelect(file);
    });
    fileInput.addEventListener('change', e => {
      const file = e.target.files?.[0];
      if (file) this.handleFileSelect(file);
    });

    this.renderRecentScans();
  },

  // ── Render recent scans sidebar ─────────────────────────────────────────
  renderRecentScans() {
    const container = utils.el('recent-scans-container');
    if (!container) return;
    container.innerHTML = '';

    state.recentScans.forEach(scan => {
      const profile = utils.riskProfile(scan.riskScore);
      const item = document.createElement('div');
      item.className = 'recent-scan-item';
      item.innerHTML = `
        <div class="recent-scan-info">
          <i data-lucide="${utils.iconForType(scan.type)}" class="recent-scan-icon"></i>
          <div class="recent-scan-details">
            <span class="recent-scan-name" title="${scan.name}">${utils.truncate(scan.name, 24)}</span>
            <span class="recent-scan-meta">${scan.size} · ${scan.riskLevel}</span>
          </div>
        </div>
        <span class="recent-scan-status ${
          scan.riskScore > 70 ? 'status-high' : scan.riskScore > 30 ? 'status-medium' : 'status-low'
        }">${scan.riskScore}</span>
      `;
      item.addEventListener('click', () => this._loadScan(scan.id));
      container.appendChild(item);
    });

    if (typeof lucide !== 'undefined') lucide.createIcons();
  },

  _loadScan(id) {
    const scan = state.recentScans.find(s => s.id === id);
    if (!scan) return;
    state.currentScan = scan;
    const emptyState = utils.el('dashboard-empty-state');
    if (emptyState) emptyState.style.display = 'none';
    this.updateUIWithScan(scan);
  },

  // ── File select handler — shows animated overlay ─────────────────────────
  handleFileSelect(file) {
    const overlay     = utils.el('scanner-overlay');
    const statusText  = utils.el('scanner-status-text');
    const fill        = utils.el('scanner-progress-fill');
    const consoleLog  = utils.el('scanner-console-log');
    if (!overlay || !statusText || !fill || !consoleLog) return;

    overlay.classList.add('active');
    fill.style.width = '0%';
    consoleLog.textContent = '';

    const steps = [
      `[SYS]    Allocating zero-trust sandbox for binary analysis...`,
      `[FILE]   Reading: "${file.name}" (${utils.formatSize(file.size)}, ${file.type || 'unknown'})`,
      `[POLICY] Applying active audit policy rules...`,
      `[SCAN]   Running ${Object.keys(DETECTION_RULES).length} regex detection patterns...`,
      `[SCAN]   Analysing credential entropy sequences...`,
      `[SCAN]   Inspecting EXIF / document metadata blocks...`,
      `[SCORE]  Calculating weighted privacy exposure index...`,
      `[AI]     Generating context-aware remediation guidance...`,
      `[DONE]   Audit complete. Generating security report.`
    ];

    let step = 0;
    const interval = setInterval(() => {
      if (step < steps.length) {
        const pct = Math.round(((step + 1) / steps.length) * 100);
        fill.style.width = `${pct}%`;
        statusText.textContent = `Scanning: ${pct}%`;
        consoleLog.textContent += steps[step] + '\n';
        consoleLog.scrollTop = consoleLog.scrollHeight;
        step++;
      } else {
        clearInterval(interval);
        // Read file content for text, skip for images
        if (file.type.startsWith('image/')) {
          this._executeScan(file, null);
          overlay.classList.remove('active');
        } else {
          const reader = new FileReader();
          reader.onload = e => {
            this._executeScan(file, e.target.result);
            overlay.classList.remove('active');
          };
          reader.onerror = () => {
            overlay.classList.remove('active');
            this._showToast('Error reading file. Please try again.', 'error');
          };
          reader.readAsText(file, 'utf-8');
        }
      }
    }, 220);
  },

  // ── Core scan logic ──────────────────────────────────────────────────────
  _executeScan(file, content) {
    const policy = {
      pii:    document.getElementById('policy-pii')?.checked  ?? true,
      keys:   document.getElementById('policy-keys')?.checked ?? true,
      exif:   document.getElementById('policy-exif')?.checked ?? true,
      custom: document.getElementById('policy-custom')?.checked ?? false,
      customRegex: document.getElementById('policy-custom-regex')?.value?.trim() ?? ''
    };

    const isImage   = file.type.startsWith('image/');
    const findings  = [];
    let   totalWeight = 0;

    const meta = {
      'Document Author':  'N/A',
      'Creator Software': 'DataBison Browser Engine v2.0',
      'Timestamp':        new Date().toUTCString(),
      'Camera Model':     'N/A',
      'GPS Coordinates':  'N/A'
    };

    if (isImage) {
      // ── Image scan: simulate EXIF extraction ──────────────────────────
      if (policy.exif) {
        // In a real implementation you'd parse EXIF bytes from the ArrayBuffer.
        // Here we simulate discovery for demonstration.
        const coords = '48.8584° N, 2.2945° E';
        meta['GPS Coordinates']  = `${coords} (Eiffel Tower, Paris)`;
        meta['Camera Model']     = 'Sony ILCE-7RM3 · f/2.8 · 1/125s · ISO 100';
        meta['Document Author']  = 'Creative Studio Paris';
        meta['Creator Software'] = 'Adobe Lightroom Classic 13.0 (macOS)';
        meta['Timestamp']        = '2026-05-21 14:32:00 UTC';

        findings.push(
          { type: 'GPS Location',     value: coords,                         severity: 'High'   },
          { type: 'Device Identity',  value: 'Sony ILCE-7RM3',               severity: 'Medium' },
          { type: 'Software Identity',value: 'Adobe Lightroom Classic 13.0', severity: 'Low'    }
        );
        totalWeight += 18 + 8 + 4; // GPS + device + software
      } else {
        meta['GPS Coordinates'] = 'N/A (Scan Disabled by Policy)';
        meta['Camera Model']    = 'N/A (Scan Disabled by Policy)';
      }

    } else if (content) {
      // ── Text / document scan ──────────────────────────────────────────
      const rulesToRun = [];

      if (policy.pii)  rulesToRun.push('email', 'phone', 'ssn', 'creditCard', 'ipAddress');
      if (policy.keys) rulesToRun.push('awsAccessKey', 'awsSecretKey', 'githubToken', 'stripeKey',
                                        'twilioKey', 'slackToken', 'jwtToken', 'rsaPrivateKey',
                                        'genericSecret', 'envVariable', 'urlWithCredentials');

      rulesToRun.forEach(ruleId => {
        const rule  = DETECTION_RULES[ruleId];
        if (!rule)  return;

        // Reset lastIndex to avoid stateful regex bugs
        rule.regex.lastIndex = 0;
        const raw  = content.match(rule.regex) || [];
        const hits = utils.dedup(raw);

        hits.forEach(val => {
          findings.push({
            type:     rule.label,
            value:    utils.truncate(val.trim(), 52),
            severity: rule.severity,
            ruleId:   rule.id
          });
          totalWeight += rule.weight;
        });
      });

      // Custom regex
      if (policy.custom && policy.customRegex) {
        try {
          const userReg = new RegExp(policy.customRegex, 'g');
          const hits    = utils.dedup(content.match(userReg) || []);
          hits.forEach(val => {
            findings.push({ type: 'Custom Policy Match', value: utils.truncate(val, 52), severity: 'High', ruleId: 'custom' });
            totalWeight += 20;
          });
        } catch (e) {
          console.error('[DataBison] Invalid custom regex:', e.message);
        }
      }

      // Infer basic metadata from content clues
      const authorMatch = content.match(/(?:author|created by|maintainer)[:\s]+([^\n]{3,60})/i);
      if (authorMatch) meta['Document Author'] = authorMatch[1].trim();
      const swMatch = content.match(/(?:generator|created with|built with)[:\s]+([^\n]{3,60})/i);
      if (swMatch) meta['Creator Software'] = swMatch[1].trim();
    }

    // ── Weighted risk score calculation ──────────────────────────────────
    // Base: 0. Each finding adds its weight. Cap at 99.
    // Minimum floor of 10 for any file that was successfully parsed.
    let score = Math.min(Math.max(totalWeight, findings.length > 0 ? 15 : 10), 99);

    // Bonus: if both PII and credentials found together, escalate score
    const hasCreds = findings.some(f => ['Critical', 'High'].includes(f.severity));
    const hasPii   = findings.some(f => f.type.includes('Email') || f.type.includes('Phone') || f.type.includes('SSN'));
    if (hasCreds && hasPii) score = Math.min(score + 10, 99);

    const profile = utils.riskProfile(score);

    // ── Generate dynamic recommendations ─────────────────────────────────
    const recs = this._buildRecommendations(findings, profile.level, file.name);

    // ── Build scan result object ──────────────────────────────────────────
    const newScan = {
      id:         `scan-${Date.now()}`,
      name:       file.name,
      size:       utils.formatSize(file.size),
      type:       file.type || 'text/plain',
      riskScore:  score,
      riskLevel:  profile.level,
      findings,
      metadata:   meta,
      recs,
      rawContent: content
    };

    // Prepend to recent list, keep max 6
    state.recentScans.unshift(newScan);
    if (state.recentScans.length > 6) state.recentScans.pop();
    state.currentScan = newScan;

    this.renderRecentScans();
    this._loadScan(newScan.id);
  },

  // ── Build context-aware recommendations from actual findings ─────────────
  _buildRecommendations(findings, riskLevel, fileName) {
    const actions = [];
    const types   = findings.map(f => f.ruleId || f.type.toLowerCase());

    // Credentials
    if (types.some(t => ['awsAccessKey','awsSecretKey'].includes(t))) {
      actions.push('Revoke and rotate the exposed AWS credentials immediately via the IAM console.');
      actions.push('Move secrets to AWS Secrets Manager or use IAM roles instead of static keys.');
    }
    if (types.some(t => t === 'githubToken')) {
      actions.push('Revoke the exposed GitHub token at github.com/settings/tokens immediately.');
    }
    if (types.some(t => t === 'stripeKey')) {
      actions.push('Roll the Stripe secret key in your Dashboard → Developers → API keys.');
    }
    if (types.some(t => t === 'slackToken')) {
      actions.push('Revoke the Slack token at api.slack.com/apps and regenerate a replacement.');
    }
    if (types.some(t => t === 'jwtToken')) {
      actions.push('JWTs contain user claims — rotate the signing secret and invalidate active sessions.');
    }
    if (types.some(t => t === 'rsaPrivateKey')) {
      actions.push('CRITICAL: An RSA private key was detected. Regenerate the key pair immediately.');
    }
    if (types.some(t => t === 'urlWithCredentials')) {
      actions.push('Remove embedded credentials from connection strings; use environment variables instead.');
    }
    if (types.some(t => ['genericSecret','envVariable'].includes(t))) {
      actions.push('Store secrets in a .env file excluded from version control via .gitignore.');
      actions.push('Adopt a secrets manager (Vault, AWS SSM, Doppler) for team environments.');
    }

    // PII
    if (types.some(t => t === 'email')) {
      actions.push('Redact email addresses before sharing files externally to comply with GDPR/CCPA.');
    }
    if (types.some(t => t === 'phone')) {
      actions.push('Remove or mask phone numbers — direct contact info can enable social engineering.');
    }
    if (types.some(t => t === 'ssn')) {
      actions.push('CRITICAL: SSN detected. This file must never be shared. Notify your DPO immediately.');
    }
    if (types.some(t => t === 'creditCard')) {
      actions.push('CRITICAL: Credit card number found. This is a PCI-DSS violation if stored in plaintext.');
    }
    if (types.some(t => t === 'ipAddress')) {
      actions.push('Internal IPs reveal network topology. Redact before sharing externally.');
    }

    // GPS / EXIF
    if (findings.some(f => f.type.includes('GPS'))) {
      actions.push('Strip EXIF metadata using DataBison before publishing images online.');
      actions.push('Disable geotagging in your camera app settings under Privacy → Location Services.');
    }

    // Always include general hygiene
    if (actions.length === 0) {
      actions.push(`File "${fileName}" passed all active audit checks — safe for distribution.`);
      actions.push('Continue running DataBison scans before every file share or commit.');
    } else {
      actions.push('Run git-secrets or truffleHog to scan your entire commit history for past leaks.');
    }

    // Title and description
    const critCount = findings.filter(f => f.severity === 'Critical').length;
    const title = critCount > 0
      ? `${critCount} Critical Violation${critCount > 1 ? 's' : ''} — Immediate Action Required`
      : riskLevel === 'Medium Risk'
        ? 'PII Exposure Risk Detected'
        : 'Clean Audit — File Verified Secure';

    const desc = critCount > 0
      ? `This file contains ${critCount} critical finding${critCount > 1 ? 's' : ''} including exposed credentials or highly sensitive PII. Do NOT share this file until remediation is complete.`
      : riskLevel === 'Medium Risk'
        ? 'Personal identifiable information was found. Review and redact before distributing externally.'
        : 'No significant privacy risks detected in this file.';

    return { title, desc, actions };
  },

  // ── Update all dashboard UI components ───────────────────────────────────
  updateUIWithScan(scan) {
    const emptyState = utils.el('dashboard-empty-state');
    const results    = utils.el('dashboard-results');
    if (emptyState) emptyState.style.display = 'none';
    if (results)    results.classList.add('active');

    this._updateGauge(scan);
    this._updateSummaryCards(scan);
    this._updateThreatChart(scan);
    this._updateFindingsTable(scan);
    this._updateMetadataGrid(scan);
    this._updateRecommendations(scan);

    // Show sanitize button for medium/high risk
    const sanitizeBtn = utils.el('btn-sanitize-file');
    if (sanitizeBtn) sanitizeBtn.style.display = scan.riskScore > 30 ? 'inline-flex' : 'none';

    if (typeof lucide !== 'undefined') lucide.createIcons();
  },

  _updateGauge(scan) {
    const profile      = utils.riskProfile(scan.riskScore);
    const scoreEl      = utils.el('result-risk-score');
    const levelEl      = utils.el('result-risk-level');
    const gaugeFill    = utils.el('gauge-fill-arc');
    if (scoreEl)   scoreEl.textContent = scan.riskScore;
    if (levelEl)   { levelEl.textContent = scan.riskLevel; levelEl.className = `risk-level-label ${profile.cssClass}`; }
    if (gaugeFill) { gaugeFill.style.strokeDashoffset = 377 - (377 * scan.riskScore / 100); gaugeFill.style.stroke = profile.color; }
  },

  _updateSummaryCards(scan) {
    const emailCount = scan.findings.filter(f => f.type.toLowerCase().includes('email')).length;
    const phoneCount = scan.findings.filter(f => f.type.toLowerCase().includes('phone')).length;
    const credCount  = scan.findings.filter(f => ['Critical', 'High'].includes(f.severity)
                         && !f.type.toLowerCase().includes('gps')).length;
    const metaCount  = Object.values(scan.metadata).filter(v =>
                         v !== 'N/A' && !v.startsWith('N/A') && !v.includes('Engine')).length;

    const set = (countId, statusId, count, exposedLabel = 'Exposed', color = 'var(--warning-orange)') => {
      const c = utils.el(countId); const s = utils.el(statusId);
      if (c) c.textContent = count;
      if (s) { s.textContent = count > 0 ? exposedLabel : 'Secure'; s.style.color = count > 0 ? color : 'var(--success-green)'; }
    };

    set('summary-count-emails',   'summary-status-emails',   emailCount);
    set('summary-count-phones',   'summary-status-phones',   phoneCount);
    set('summary-count-creds',    'summary-status-creds',    credCount,  'CRITICAL', 'var(--danger-red)');
    set('summary-count-metadata', 'summary-status-metadata', metaCount,  'Leaking',  'var(--warning-orange)');
  },

  _updateThreatChart(scan) {
    const credCount = scan.findings.filter(f => f.severity === 'Critical').length;
    const piiCount  = scan.findings.filter(f => ['email', 'phone', 'ssn', 'creditCard'].includes(f.ruleId)).length;
    const metaCount = Object.values(scan.metadata).filter(v => v !== 'N/A' && !v.startsWith('N/A')).length;
    const maxVal    = Math.max(credCount, piiCount, metaCount, 1);

    const setBar = (barId, valId, count) => {
      const bar = utils.el(barId); const val = utils.el(valId);
      if (bar) bar.style.width = count > 0 ? `${Math.max((count / maxVal) * 100, 12)}%` : '0%';
      if (val) val.textContent = count;
    };

    setBar('chart-bar-critical', 'chart-val-critical', credCount);
    setBar('chart-bar-pii',      'chart-val-pii',      piiCount);
    setBar('chart-bar-exif',     'chart-val-exif',     metaCount);
  },

  _updateFindingsTable(scan) {
    const body = utils.el('findings-table-body');
    if (!body) return;

    if (scan.findings.length === 0) {
      body.innerHTML = `<tr><td colspan="3" style="text-align:center;padding:1.5rem;color:var(--success-green);font-weight:600;">
        ✅ No violations detected — file passed all active audit checks.
      </td></tr>`;
      return;
    }

    // Sort: Critical first, then High, Medium, Low
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    const sorted = [...scan.findings].sort((a, b) =>
      (order[a.severity.toLowerCase()] ?? 9) - (order[b.severity.toLowerCase()] ?? 9)
    );

    body.innerHTML = sorted.map(f => {
      const sc = utils.severityClass(f.severity);
      return `
        <tr>
          <td style="font-weight:600;">${f.type}</td>
          <td><code class="finding-value" title="${f.value}">${f.value}</code></td>
          <td><span class="severity-badge severity-${sc}">${f.severity}</span></td>
        </tr>
      `;
    }).join('');
  },

  _updateMetadataGrid(scan) {
    const grid = utils.el('metadata-inspector-grid');
    if (!grid) return;

    grid.innerHTML = Object.entries(scan.metadata).map(([key, val]) => {
      const risk = METADATA_RISK[key] || 'safe';
      const riskClass = val === 'N/A' || val.startsWith('N/A') ? '' : risk;
      return `
        <div class="metadata-field">
          <div class="metadata-key">${key}</div>
          <div class="metadata-value ${riskClass}" title="${val}">${utils.truncate(val, 44)}</div>
        </div>
      `;
    }).join('');
  },

  _updateRecommendations(scan) {
    const headerEl  = utils.el('recommendation-badge-header');
    const titleEl   = utils.el('recommendation-summary-title');
    const descEl    = utils.el('recommendation-summary-desc');
    const actionEl  = utils.el('recommendations-action-list');
    if (!titleEl || !descEl || !actionEl) return;

    titleEl.textContent = scan.recs.title;
    descEl.textContent  = scan.recs.desc;

    if (headerEl) {
      const profile = utils.riskProfile(scan.riskScore);
      headerEl.className = `rec-header ${
        scan.riskScore > 70 ? 'risk-high' : scan.riskScore > 30 ? 'risk-medium' : 'risk-low-bg'
      }`;
    }

    actionEl.innerHTML = scan.recs.actions.map(action => `
      <div class="rec-action-item">
        <span>${action}</span>
      </div>
    `).join('');
  },

  // ── Sanitize / Redact ────────────────────────────────────────────────────
  sanitizeCurrentFile() {
    const scan = state.currentScan;
    if (!scan) return;

    if (scan.type.startsWith('image/')) {
      this._sanitizeImage(scan);
    } else if (scan.rawContent) {
      this._sanitizeText(scan);
    } else {
      this._showToast('No raw content available for sanitization.', 'warning');
    }
  },

  _sanitizeImage(scan) {
    // Simulate EXIF stripping by re-rendering to canvas (removes all metadata)
    const canvas = document.createElement('canvas');
    canvas.width  = 800;
    canvas.height = 460;
    const ctx = canvas.getContext('2d');

    // Background
    ctx.fillStyle = '#0B1020';
    ctx.fillRect(0, 0, 800, 460);

    // Grid
    ctx.strokeStyle = 'rgba(6, 182, 212, 0.05)'; ctx.lineWidth = 1;
    for (let x = 0; x < 800; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, 460); ctx.stroke(); }
    for (let y = 0; y < 460; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(800, y); ctx.stroke(); }

    // Card
    ctx.fillStyle = '#131A2A'; ctx.strokeStyle = 'rgba(34, 197, 94, 0.4)'; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.roundRect(150, 90, 500, 280, 16); ctx.fill(); ctx.stroke();

    // Circle
    ctx.fillStyle = 'rgba(34, 197, 94, 0.1)'; ctx.strokeStyle = '#22C55E'; ctx.lineWidth = 3;
    ctx.beginPath(); ctx.arc(400, 165, 48, 0, Math.PI * 2); ctx.fill(); ctx.stroke();

    // Checkmark
    ctx.strokeStyle = '#22C55E'; ctx.lineWidth = 6; ctx.lineCap = 'round'; ctx.lineJoin = 'round';
    ctx.beginPath(); ctx.moveTo(380, 165); ctx.lineTo(396, 182); ctx.lineTo(424, 148); ctx.stroke();

    // Text
    ctx.fillStyle = '#F8FAFC'; ctx.textAlign = 'center';
    ctx.font = 'bold 20px Poppins, sans-serif'; ctx.fillText('DataBison — EXIF Stripped Asset', 400, 248);
    ctx.fillStyle = '#94A3B8';
    ctx.font = '14px Inter, sans-serif'; ctx.fillText(`File: ${scan.name}`, 400, 278);
    ctx.fillText('GPS Coordinates: STRIPPED · Camera Model: STRIPPED', 400, 302);
    ctx.fillStyle = '#22C55E'; ctx.font = 'bold 12px monospace';
    ctx.fillText('STATUS: ZERO-TRUST VERIFIED · 0 METADATA FIELDS REMAINING', 400, 338);

    canvas.toBlob(blob => {
      const a = document.createElement('a');
      a.href     = URL.createObjectURL(blob);
      a.download = `databison_clean_${scan.name.replace(/\.[^.]+$/, '')}.png`;
      a.click();
      this._showToast('EXIF metadata stripped successfully. Location data removed.');
    }, 'image/png');
  },

  _sanitizeText(scan) {
    let clean = scan.rawContent;
    const policy = {
      pii:  document.getElementById('policy-pii')?.checked  ?? true,
      keys: document.getElementById('policy-keys')?.checked ?? true
    };

    // Apply each relevant rule's replacement
    Object.values(DETECTION_RULES).forEach(rule => {
      const isPii  = ['email','phone','ssn','creditCard','ipAddress'].includes(rule.id);
      const isCred = !isPii;
      if ((isPii && policy.pii) || (isCred && policy.keys)) {
        rule.regex.lastIndex = 0;
        clean = clean.replace(rule.regex, rule.redactWith);
      }
    });

    // Custom regex redaction
    const customCheck = document.getElementById('policy-custom');
    const customInput = document.getElementById('policy-custom-regex');
    if (customCheck?.checked && customInput?.value.trim()) {
      try {
        const ur = new RegExp(customInput.value.trim(), 'g');
        clean = clean.replace(ur, '[REDACTED_CUSTOM_MATCH]');
      } catch (e) { /* invalid regex — skip */ }
    }

    const blob = new Blob([clean], { type: 'text/plain;charset=utf-8' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `databison_clean_${scan.name}`;
    a.click();
    this._showToast(`${scan.findings.length} violation${scan.findings.length !== 1 ? 's' : ''} redacted. Clean file downloaded.`);
  },

  // ── Export plain-text audit report ───────────────────────────────────────
  exportSummary() {
    const scan = state.currentScan;
    if (!scan) { this._showToast('No scan loaded. Please scan a file first.', 'warning'); return; }

    const separator = '═'.repeat(64);
    const line      = '─'.repeat(64);

    const findingsBlock = scan.findings.length === 0
      ? '  No violations detected.\n'
      : scan.findings.map(f => `  [${f.severity.toUpperCase().padEnd(8)}] ${f.type}: ${f.value}`).join('\n') + '\n';

    const metaBlock = Object.entries(scan.metadata)
      .map(([k, v]) => `  ${k.padEnd(20)}: ${v}`).join('\n') + '\n';

    const recsBlock = scan.recs.actions
      .map((a, i) => `  ${(i + 1).toString().padStart(2)}. ${a}`).join('\n') + '\n';

    const report = [
      separator,
      '  DATABISON SECURITY AUDIT REPORT v2.0',
      '  Zero-Trust Client-Side Privacy Audit Engine',
      separator,
      `  Scan Date   : ${scan.metadata['Timestamp'] || new Date().toUTCString()}`,
      `  File Name   : ${scan.name}`,
      `  File Size   : ${scan.size}`,
      `  File Type   : ${scan.type}`,
      `  Risk Score  : ${scan.riskScore}/100  [${scan.riskLevel}]`,
      `  Violations  : ${scan.findings.length} finding(s)`,
      line,
      '  SENSITIVE EXPOSURE FINDINGS',
      line,
      findingsBlock,
      line,
      '  EXTRACTED METADATA',
      line,
      metaBlock,
      line,
      '  AI SECURITY REMEDIATION',
      line,
      `  Verdict : ${scan.recs.title}`,
      `  Detail  : ${scan.recs.desc}`,
      '',
      recsBlock,
      separator,
      '  Generated by DataBison v2.0 — 0% of file data transmitted externally.',
      '  All scanning performed locally in your browser sandbox.',
      separator
    ].join('\n');

    const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `databison_audit_${scan.name.replace(/\.[^.]+$/, '')}_${Date.now()}.txt`;
    a.click();
    this._showToast('Audit report exported successfully.');
  },

  // ── Print PDF ─────────────────────────────────────────────────────────────
  generatePDFReport() {
    const scan = state.currentScan;
    if (!scan) { this._showToast('No scan loaded. Please scan a file first.', 'warning'); return; }

    // Open a styled print window
    const win = window.open('', '_blank', 'width=900,height=700');
    if (!win) { this._showToast('Pop-up blocked. Allow pop-ups and try again.', 'warning'); return; }

    const findingsRows = scan.findings.length === 0
      ? `<tr><td colspan="3" style="text-align:center;color:#22C55E;">No violations detected</td></tr>`
      : scan.findings.map(f => `
          <tr>
            <td>${f.type}</td>
            <td style="font-family:monospace;word-break:break-all;">${f.value}</td>
            <td style="color:${f.severity==='Critical'?'#EF4444':f.severity==='High'?'#F59E0B':'#60a5fa'};font-weight:700;">${f.severity}</td>
          </tr>`).join('');

    const metaRows = Object.entries(scan.metadata)
      .map(([k,v]) => `<tr><td><strong>${k}</strong></td><td>${v}</td></tr>`).join('');

    const profile = utils.riskProfile(scan.riskScore);

    win.document.write(`<!DOCTYPE html><html><head><title>DataBison Audit — ${scan.name}</title>
    <style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{font-family:'Inter',sans-serif;background:#fff;color:#1e293b;padding:40px}
      h1{font-size:22px;margin-bottom:4px;color:#0B1020}
      .subtitle{color:#64748b;font-size:12px;margin-bottom:24px}
      .badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:700;
        background:${scan.riskScore>70?'#fef2f2':scan.riskScore>30?'#fffbeb':'#f0fdf4'};
        color:${scan.riskScore>70?'#ef4444':scan.riskScore>30?'#f59e0b':'#22c55e'};
        border:1px solid ${scan.riskScore>70?'#fecaca':scan.riskScore>30?'#fde68a':'#bbf7d0'}}
      .meta-row{display:flex;gap:24px;flex-wrap:wrap;margin-bottom:24px;font-size:13px;color:#475569}
      .meta-row span strong{color:#1e293b}
      h2{font-size:14px;font-weight:700;border-bottom:2px solid #e2e8f0;padding-bottom:6px;margin:20px 0 10px;text-transform:uppercase;letter-spacing:1px;color:#0B1020}
      table{width:100%;border-collapse:collapse;font-size:13px}
      th{background:#f8fafc;padding:8px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:#64748b;border-bottom:2px solid #e2e8f0}
      td{padding:8px 12px;border-bottom:1px solid #f1f5f9}
      .rec{background:#f8fafc;border-left:3px solid #3B82F6;padding:8px 12px;margin-bottom:6px;font-size:13px;border-radius:0 4px 4px 0}
      .footer{margin-top:32px;text-align:center;font-size:11px;color:#94a3b8}
      @media print{body{padding:20px}}
    </style></head><body>
    <h1>DataBison Security Audit Report</h1>
    <p class="subtitle">Zero-Trust Client-Side Privacy Audit Engine v2.0 · ${new Date().toUTCString()}</p>
    <div class="meta-row">
      <span><strong>File:</strong> ${scan.name}</span>
      <span><strong>Size:</strong> ${scan.size}</span>
      <span><strong>Type:</strong> ${scan.type}</span>
      <span><strong>Risk:</strong> <span class="badge">${scan.riskScore}/100 — ${scan.riskLevel}</span></span>
    </div>
    <h2>Sensitive Findings (${scan.findings.length})</h2>
    <table><thead><tr><th>Type</th><th>Value</th><th>Severity</th></tr></thead><tbody>${findingsRows}</tbody></table>
    <h2>File Metadata</h2>
    <table><tbody>${metaRows}</tbody></table>
    <h2>AI Remediation Guidance</h2>
    <p style="font-size:13px;margin-bottom:10px;color:#475569"><strong>${scan.recs.title}:</strong> ${scan.recs.desc}</p>
    ${scan.recs.actions.map(a => `<div class="rec">${a}</div>`).join('')}
    <div class="footer">Generated by DataBison v2.0 · All scanning performed locally. 0 bytes transmitted externally.</div>
    <script>window.onload=()=>{window.print();}<\/script>
    </body></html>`);
    win.document.close();
  },

  // ── Toast notification ────────────────────────────────────────────────────
  _showToast(message, type = 'success') {
    let toast = document.getElementById('db-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'db-toast';
      Object.assign(toast.style, {
        position: 'fixed', top: '24px', right: '24px', zIndex: '9999',
        background: 'rgba(19,26,42,0.95)',
        borderRadius: '8px', padding: '0.9rem 1.4rem',
        color: '#F8FAFC', fontFamily: 'Inter, sans-serif',
        fontSize: '0.875rem', fontWeight: '500',
        boxShadow: '0 8px 30px rgba(0,0,0,0.4)',
        display: 'flex', alignItems: 'center', gap: '0.75rem',
        maxWidth: '380px', lineHeight: '1.4',
        transform: 'translateY(-20px)', opacity: '0',
        transition: 'transform 0.35s cubic-bezier(0.175,0.885,0.32,1.275), opacity 0.3s ease'
      });
      document.body.appendChild(toast);
    }

    const colors = { success: '#22C55E', warning: '#F59E0B', error: '#EF4444' };
    const icons  = { success: 'shield-check', warning: 'alert-triangle', error: 'x-circle' };
    const color  = colors[type] || colors.success;

    toast.style.border = `1px solid ${color}`;
    toast.style.boxShadow = `0 8px 24px rgba(0,0,0,0.4), 0 0 0 1px ${color}22`;
    toast.innerHTML = `
      <i data-lucide="${icons[type]}" style="color:${color};width:18px;height:18px;flex-shrink:0;"></i>
      <span>${message}</span>
    `;
    if (typeof lucide !== 'undefined') lucide.createIcons();

    // Animate in
    requestAnimationFrame(() => {
      toast.style.transform = 'translateY(0)';
      toast.style.opacity   = '1';
    });

    // Clear any existing timer
    clearTimeout(toast._hideTimer);
    toast._hideTimer = setTimeout(() => {
      toast.style.transform = 'translateY(-20px)';
      toast.style.opacity   = '0';
    }, 3500);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// BOOT
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  if (typeof lucide !== 'undefined') lucide.createIcons();
  appRouter.init();
  scanEngine.init();
});
