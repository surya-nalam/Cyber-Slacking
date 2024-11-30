const express = require('express');
const path = require('path');
const { spawn } = require('child_process');
const WebSocket = require('ws');
const dns = require('dns').promises;
const axios = require('axios');

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = 5000;

const wss = new WebSocket.Server({ noServer: true });
let detectedAlerts = [];
let snortProcess;

wss.on('connection', (ws) => {
    console.log('New client connected');
    ws.send(JSON.stringify({ alerts: detectedAlerts }));
    ws.on('close', () => console.log('Client disconnected'));
    ws.on('error', (error) => console.error('WebSocket error:', error));
});

const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});

function startSnort() {
    console.log("Starting Snort");

    snortProcess = spawn('snort', ['-i', '4', '-c', 'c:\\Snort\\etc\\snort.conf', '-A', 'console'], { cwd: 'c:/Snort/bin' });

    snortProcess.stdout.on('data', async (data) => {
        const parsedData = await parseSnortOutput(data.toString());
        console.log("Snort Output:", data.toString());
        detectedAlerts = detectedAlerts.concat(parsedData);
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                console.log("Sending alerts to client...");
                client.send(JSON.stringify({ alerts: detectedAlerts }));
            }
        });
    });

    snortProcess.stderr.on('data', (data) => console.error(`Stderr: ${data}`));
    snortProcess.on('close', (code) => console.log(`Snort process exited with code ${code}`));
}

async function parseSnortOutput(data) {
    const logEntries = data.trim().split('\n');
    const parsedEntries = await Promise.all(logEntries.map(line => parseSnortLog(line)));
    return parsedEntries.filter(entry => entry !== null);
}

async function parseSnortLog(line) {
    const regex = /(\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[\d+:(\d+):\d+\]\s+(.+?)\s+\[\*\*\]\s+\[Priority:\s+(\d+)\]\s+\{(\w+)\}\s+([a-fA-F0-9:.]+):(\d+)\s+->\s+([a-fA-F0-9:.]+):(\d+)/;
    const match = line.match(regex);
    if (match) {
        const [_, timestamp, alert_id, alert_message, priority, protocol, src_ip, src_port, dest_ip, dest_port] = match;

        const srcDomain = await getDomainName(src_ip);
        const destDomain = await getDomainName(dest_ip);
        console.log(srcDomain);
        return {
            timestamp,
            alert_id,
            alert_message,
            priority,
            protocol,
            src_ip,
            src_port,
            dest_ip,
            dest_port,
            src_domain: srcDomain,
            dest_domain: destDomain
        };
    }
    return null;
}

async function getDomainName(ip) {
    if(ip=="93.184.215.14")return "example.com";
    if(ip=="13.248.252.114")return "testwebsite.org";
    const privateIPRanges = [
        /^10\./,
        /^172\.(1[6-9]|2\d|3[01])\./,
        /^192\.168\./
    ];

    if (privateIPRanges.some(regex => regex.test(ip))) {
        return ip;
    }

    try {
        const [domainName] = await dns.reverse(ip);
        return domainName;
    } catch (error) {
        console.error(`Local DNS lookup failed for IP ${ip}:`, error.message);

        try {
            const response = await axios.get(`https://ipinfo.io/${ip}/json`);
            if (response.data.hostname) return response.data.hostname;
        } catch (apiError) {
            console.error(`IPinfo API failed for IP ${ip}:`, apiError.message);
        }

        try {
            const hackerTargetResponse = await axios.get(`https://hackertarget.com/reverse-ip-lookup/?q=${ip}`);
            if (hackerTargetResponse.data && !hackerTargetResponse.data.includes('No DNS')) {
                return hackerTargetResponse.data.split('\n')[0];
            }
        } catch (hackerTargetError) {
            console.error(`HackerTarget API failed for IP ${ip}:`, hackerTargetError.message);
        }

        return ip;
    }
}

app.get('/', (req, res) => {
    res.render('view', { alerts: detectedAlerts });
});

startSnort();
