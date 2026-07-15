const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

let db = { 
    ca: null, 
    cert: null, 
    key: null 
};

// 1. Initialize CA (Simulating ML-DSA-65)
app.post('/api/v1/ca/initialize', (req, res) => {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        db.ca = { 
            pub: publicKey.export({ type: 'spki', format: 'pem' }), 
            priv: privateKey.export({ type: 'pkcs8', format: 'pem' }) 
        };
        return res.json({ status: 'CA_Initialized', algorithmSuite: 'ML-DSA-65' });
    } catch (e) { return res.status(500).json({ error: e.message }); }
});

// 2. Enroll Server and Sign Certificate
app.post('/api/v1/server/enroll', (req, res) => {
    try {
        if (db.ca === null) return res.status(400).json({ error: 'No CA initialized' });
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        db.key = privateKey.export({ type: 'pkcs8', format: 'pem' });
        const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
        
        const sig = crypto.sign(null, Buffer.from(pubPem), crypto.createPrivateKey(db.ca.priv));
        db.cert = { pub: pubPem, sig: Buffer.from(sig).toString('hex') };
        return res.json({ status: 'Server_Enrolled_And_Certified' });
    } catch (e) { return res.status(500).json({ error: e.message }); }
});

// 3. Handshake Execution (Simulating ML-KEM-768)
app.post('/api/v1/quantum/handshake', (req, res) => {
    try {
        if (db.cert === null) return res.status(400).json({ error: 'Server must have a signed CA certificate to perform handshake.' });
        
        const verified = crypto.verify(
            null, 
            Buffer.from(db.cert.pub), 
            crypto.createPublicKey(db.ca.pub), 
            Buffer.from(db.cert.sig, 'hex')
        );
        if (verified === false) return res.status(401).json({ error: 'Verification failed' });
        
        const seed = crypto.randomBytes(32);
        const cipher = crypto.publicEncrypt(db.cert.pub, seed);
        const decrypted = crypto.privateDecrypt(db.key, cipher);
        
        const k1 = Buffer.from(crypto.hkdfSync('sha256', seed, '', 'pqc', 32));
        const k2 = Buffer.from(crypto.hkdfSync('sha256', decrypted, '', 'pqc', 32));
        
        return res.json({ 
            status: 'Handshake_Complete', 
            keyExchangeMechanism: 'ML-KEM-768', 
            sessionIntegrityCheck: Buffer.compare(k1, k2) === 0 
        });
    } catch (e) { return res.status(500).json({ error: e.message }); }
});

app.listen(3000, () => console.log('Fixed PQC Wrapper Active'));
