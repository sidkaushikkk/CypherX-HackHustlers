const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const axios = require("axios");

const GOOGLE_API_KEY = "AIzaSyASQ2eMvbH5BF9AuMPPQT4qCm-NuZnSdY4";

// Load phishing database
let phishingDb = [];
try {
    const data = fs.readFileSync(path.join(__dirname, 'phishing-db.json'), 'utf8');
    phishingDb = JSON.parse(data);
    console.log(`Loaded ${phishingDb.length} phishing domains from database.`);
} catch (err) {
    console.error("Error reading phishing-db.json", err);
}

const keywords = [
    'login', 'verify', 'secure', 'update', 'bank', 'account', 'signin', 'confirm', 
    'password', 'payment', 'alert', 'suspended', 'reset', 'free', 'gift', 'bonus', 
    'crypto', 'win', 'lottery', 'refund', 'kyc', 'wallet', 'upi'
];

const suspiciousExtensions = ['.ru', '.tk', '.ml', '.xyz', '.click'];

app.post('/api/scan-url', async (req, res) => {
        let { url, source = 'manual' } = req.body;
    
    if (!url) {
        return res.status(400).json({ status: 'ERROR', reasons: ['URL is required.'], riskScore: 0 });
    }

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
    }

    try {
        const parsedUrl = new URL(url);
        const hostname = parsedUrl.hostname.toLowerCase();
        let riskScore = 0;
        let reasons = [];
        
        // 1. Blacklist check
        for (const blacklisted of phishingDb) {
            if (hostname === blacklisted || hostname.endsWith('.' + blacklisted)) {
                riskScore = 100;
                reasons.push(`Domain matches known phishing blacklist (${blacklisted}).`);
                return res.json({ riskScore, status: 'DANGEROUS', reasons });
            }
        }
        
        // 2. Keyword check
        const pathStr = parsedUrl.pathname.toLowerCase();
        let keywordCount = 0;
        let foundKeywords = [];
        keywords.forEach(keyword => {
            if (hostname.includes(keyword) || pathStr.includes(keyword)) {
                keywordCount++;
                foundKeywords.push(keyword);
            }
        });
        
        if (keywordCount > 0) {
            riskScore += (keywordCount * 20);
            reasons.push(`Contains suspicious keywords: ${foundKeywords.join(', ')}.`);
        }

        // 3. Numbers replacing letters (simple heuristic checking for digit mixed with chars or paypa1 type)
        if (hostname.match(/[a-z]+[0-9]+[a-z]+/i) || hostname.includes('paypa1')) {
            riskScore += 30;
            reasons.push('Domain contains numbers commonly replacing letters (typosquatting).');
        }

        // 4. Many hyphens
        if ((hostname.match(/-/g) || []).length >= 3) {
            riskScore += 25;
            reasons.push('Unusually high number of hyphens in domain.');
        }

        // 5. IP Address
        const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname);
        if (isIp) {
            riskScore += 60;
            reasons.push('Uses an IP address instead of a standard domain name.');
        }

        // 6. Suspicious domain extensions
        for (const ext of suspiciousExtensions) {
            if (hostname.endsWith(ext)) {
                riskScore += 40;
                reasons.push(`Uses uncommon, highly-abused top-level domain (${ext}).`);
                break;
            }
        }

        // 7. URL length
        if (url.length > 60) {
            riskScore += 15;
            reasons.push('URL length is suspiciously long (>60 chars).');
        }

        // 8. Google Safe Browsing API check
try {

    const isUnsafe = await checkGoogleSafeBrowsing(url);

    if (isUnsafe) {

        riskScore += 70;

        reasons.push('Flagged by Google Safe Browsing database.');

    }

} catch (err) {

    console.log("Safe browsing check failed", err.message);

}

        riskScore = Math.min(riskScore, 100);

        let status = 'SAFE';
        if (riskScore >= 71) {
            status = 'DANGEROUS';
            if (reasons.length === 0) reasons.push('High-risk indicators discovered.');
        } else if (riskScore > 30) {
            status = 'SUSPICIOUS';
            if (reasons.length === 0) reasons.push('Suspicious patterns observed.');
        }

        if (riskScore === 0 && reasons.length === 0) {
            reasons.push('No obvious threats detected. URL seems clean.');
        }

        return res.json({ riskScore, status, reasons });
        
    } catch (e) {
        return res.json({ riskScore: 60, status: 'SUSPICIOUS', reasons: ['Malformed or invalid URL. Could be an evasion attempt.'] });
    }
});

// File mock endpoint mapping the old logic for dashboard
app.post('/api/scan-file', (req, res) => {
    const { filename } = req.body;
    const isDangerous = filename && (filename.endsWith('.exe') || filename.endsWith('.bat') || filename.endsWith('.vbs') || filename.includes('crack'));
    
    setTimeout(() => {
        if (isDangerous) {
            res.json({ status: 'DANGEROUS', reasons: ['Signature matched Trojan.Generic.AutoKMS or similar malware.'], riskScore: 95 });
        } else {
            res.json({ status: 'SAFE', reasons: ['No threats found. File appears clean.'], riskScore: 0 });
        }
    }, 2000);
});

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`CypherX Backend running on http://localhost:${PORT}`);
    });
}
module.exports = app;

async function checkGoogleSafeBrowsing(url) {

    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`;

    const body = {
        client: {
            clientId: "cypherx",
            clientVersion: "1.0"
        },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [
                { url }
            ]
        }
    };

    try {

        const response = await axios.post(endpoint, body);

        if (response.data && response.data.matches) {
            return true;
        }

        return false;

    } catch (error) {

        console.log("Google API error", error.message);
        return false;

    }
}
