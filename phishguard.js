function analyzeURL() {
  const url = document.getElementById("url").value.trim();
  let output = "";

  if (!url) {
    output = "<span class='alert'>Critical: Please enter a URL for analysis.</span>";
  } else {
    const patterns = [
      { regex: /http:\/\/|https:\/\/(?!.*:\/\/(www\.)?[\w-]+\.[a-z]{2,})([\w-]+\.)?[\w-]+\.[a-z]{2,}/i, reason: "Non-standard or suspicious domain structure." },
      { regex: /@/, reason: "'@' symbol detected in URL (may obscure real destination)." },
      { regex: /[-_.]{2,}/, reason: "Unusual repetition of '.', '-', or '_' in domain or path." },
      { regex: /(login|secure|account|update|bank|verify|paypal|ebay|appleid|signin|webscr|wp-admin|confirm)/i, reason: "Phishing-related keywords in URL path." },
      { regex: /xn--/, reason: "Punycode detected (may be used to spoof domains visually)." },
      { regex: /:\/\/.*\d{1,3}(\.\d{1,3}){3}/, reason: "Direct IP address used instead of domain." },
      { regex: /(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd)/i, reason: "Known URL shortener detected." },
      { regex: /\?.*=/, reason: "Suspicious query string present (possible credential harvesting)." }
    ];
    let reasons = [];
    patterns.forEach(({regex, reason}) => {
      if (regex.test(url)) reasons.push(reason);
    });

    // Additional: check for https, subdomain length, and TLD
    try {
      let parsed = new URL(url);
      if (parsed.protocol !== "https:") reasons.push("Not using secure HTTPS protocol.");
      let domainParts = parsed.hostname.split('.');
      if (domainParts.length > 4) reasons.push("Excessively long subdomain chain.");
      if (!/\.([a-z]{2,})$/.test(parsed.hostname)) reasons.push("Unusual or missing TLD.");
    } catch (e) {
      reasons.push("URL could not be parsed correctly. Input may be malformed.");
    }

    if (reasons.length > 0) {
      output = `<span class="alert"><strong>Critical:</strong> This URL exhibits multiple red flags:<ul>`;
      reasons.forEach(r => output += `<li>${r}</li>`);
      output += `</ul><span style="color:#feae19;">Recommendation: Do not trust or click this link. Conduct further verification and alert your IT/security team if relevant.</span></span>`;
    } else {
      output = `<span class="safe"><strong>No immediate critical issues detected in URL structure.</strong><br>However, always validate the sender/source and never assume safety based solely on automated analysis.</span>`;
    }
  }
  document.getElementById("output").innerHTML = output;
}

function analyzeHeaders() {
  const headers = document.getElementById("headers").value.trim();
  let output = "";
  if (!headers) {
    output = "<span class='alert'>Critical: Please paste email headers for inspection.</span>";
  } else {
    let warnings = [];
    // Look for multiple relays and IPs in headers
    const receivedCount = (headers.match(/Received:/g) || []).length;
    if (receivedCount > 3) warnings.push(`Multiple 'Received' headers detected (${receivedCount}). High relay count is typical of spoofed or relayed messages.`);
    if (/X\-Mailer: (Microsoft Outlook|Apple Mail|Thunderbird|none)/i.test(headers) === false) {
      warnings.push("Unusual, missing, or generic 'X-Mailer' header.");
    }
    if (/From: .*@(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com)/i.test(headers) && /Return-Path:.*@.*(?!gmail\.com|yahoo\.com|outlook\.com|hotmail\.com)/i.test(headers)) {
      warnings.push("'From' and 'Return-Path' domains do not match. Possible spoofing.");
    }
    if (/Reply-To:/i.test(headers) && !/Reply-To:.*@(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com)/i.test(headers)) {
      warnings.push("'Reply-To' uses an uncommon or unrelated domain.");
    }
    if (/spf=fail|dmarc=fail|dkim=fail/i.test(headers)) {
      warnings.push("SPF, DKIM, or DMARC authentication checks failed (critical red flag).");
    }
    if (/X-Originating-IP:/i.test(headers)) {
      const originIp = headers.match(/X-Originating-IP:\s*\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/i);
      if (originIp && !originIp[1].startsWith('192.168') && !originIp[1].startsWith('10.') && !originIp[1].startsWith('172.')) {
        warnings.push(`Unusual originating IP address found: ${originIp[1]}`);
      }
    }
    if (/Return-Path:.*noreply/i.test(headers)) {
      warnings.push("Return-Path uses 'noreply'—be cautious of automated phishing campaigns.");
    }
    if (warnings.length) {
      output = `<span class="alert"><strong>Critical:</strong> Email header analysis highlights the following risks:<ul>`;
      warnings.forEach(w => output += `<li>${w}</li>`);
      output += `</ul><span style="color:#feae19;">Recommendation: Treat this email as suspicious. Validate sender authenticity using out-of-band communication.</span></span>`;
    } else {
      output = `<span class="safe"><strong>No critical header anomalies detected.</strong><br>However, header analysis alone is insufficient—verify sender identity and context manually.</span>`;
    }
  }
  document.getElementById("output").innerHTML = output;
}

function analyzeContent() {
  const content = document.getElementById("content").value.trim();
  let output = "";
  if (!content) {
    output = "<span class='alert'>Critical: Please paste email content for evaluation.</span>";
  } else {
    let redFlags = [];
    if (/(urgent|immediately|asap|verify your account|reset your password|update your info|account suspended|security alert|click (here|the link)|unusual activity|confirm your identity|login to avoid suspension)/i.test(content)) {
      redFlags.push("Language engineered to induce panic, urgency, or compliance.");
    }
    if (/(http:\/\/|https:\/\/).{0,45}(login|secure|update|confirm|bank|paypal|signin|webscr|wp-admin|appleid)/i.test(content)) {
      redFlags.push("Embedded links with phishing-related keywords.");
    }
    if (/(password|ssn|credit card|security code|pin number|personal info|payment information)/i.test(content)) {
      redFlags.push("Requests for highly sensitive information.");
    }
    if (/(attachment|open the file|download|see attached|invoice attached|review document)/i.test(content)) {
      redFlags.push("Encouragement to open/download attachments—common malware vector.");
    }
    if (/unusual (login|activity|attempt)/i.test(content)) {
      redFlags.push("Mentions of 'unusual activity'—a classic phishing trigger phrase.");
    }
    if (/Dear (Customer|User|Client|Member)/.test(content)) {
      redFlags.push("Generic salutation detected, not personalized.");
    }
    if (/You have been selected|Congratulations|You won|Claim your prize/i.test(content)) {
      redFlags.push("Classic scam or social engineering language.");
    }

    if (redFlags.length) {
      output = `<span class="alert"><strong>Critical:</strong> The following phishing patterns were detected in content:<ul>`;
      redFlags.forEach(r => output += `<li>${r}</li>`);
      output += `</ul><span style="color:#feae19;">Recommendation: Do not respond, click links, or open attachments. Report this message to your security team immediately.</span></span>`;
    } else {
      output = `<span class="safe"><strong>No critical phishing language detected.</strong><br>Remain observant: sophisticated attacks may use subtle or well-crafted language. Never trust unsolicited emails at face value.</span>`;
    }
  }
  document.getElementById("output").innerHTML = output;
}