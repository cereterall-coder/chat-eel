const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// --- CONFIGURATION --- //
const ALLOWED_IP_RANGE = {
    start: { octets: [172, 27, 50, 1] },
    end: { octets: [172, 27, 56, 250] }
};

// Helper: Check if IP is allowed
function isIpAllowed(ip) {
    if (ip.startsWith('::ffff:')) {
        ip = ip.substr(7);
    }
    console.log(`Verificando acceso para IP: ${ip}`);
    if (ip === '127.0.0.1' || ip === '::1') return true;
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;
    if (parts[0] !== 172 || parts[1] !== 27) return false;
    const octet3 = parts[2];
    const octet4 = parts[3];
    if (octet3 < 50 || octet3 > 60) return false;
    if (octet3 === 50 && octet4 < 1) return false;
    // Removed strict upper limit for last octet to allow full range up to 60.255
    return true;
}

// --- MIDDLEWARE --- //
app.use(express.json()); // Allow JSON body
app.use((req, res, next) => {
    const clientIp = req.ip || req.socket.remoteAddress;
    if (isIpAllowed(clientIp)) {
        next();
    } else {
        res.status(403).send(`
            <div style="font-family: sans-serif; text-align: center; margin-top: 50px; color: #333;">
                <h1 style="color: #d32f2f;">Acceso Denegado</h1>
                <p>Su dirección IP (<strong>${clientIp}</strong>) no está autorizada para acceder a Chat-ELL.</p>
                <p style="color: #666;">Rango permitido: 172.27.50.1 - 172.27.60.255</p>
            </div>
        `);
    }
});

app.use(express.static('public'));

// ... (rest of the file until API section)

// --- API FOR AUDIT ---
app.get('/api/audit', (req, res) => {
    // Simple mock auth
    const auth = req.headers['x-admin-key'];
    if (auth !== 'Alexis2026') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    if (fs.existsSync(LOG_FILE)) {
        res.json(JSON.parse(fs.readFileSync(LOG_FILE)));
    } else {
        res.json([]);
    }
});

// Delete Logs API
app.post('/api/audit/delete', (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== 'Alexis2026') return res.status(403).json({ error: 'Unauthorized' });

    const { start, end } = req.body;
    if (!start || !end) return res.status(400).json({ error: 'Missing params' });

    let logs = [];
    if (fs.existsSync(LOG_FILE)) {
        try { logs = JSON.parse(fs.readFileSync(LOG_FILE)); } catch (e) { }
    }

    const initialCount = logs.length;
    // Keep logs that are OUTSIDE the range
    logs = logs.filter(log => log.timestamp < start || log.timestamp > end);

    fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));

    res.json({ success: true, deleted: initialCount - logs.length });
});

// --- STATE --- //
const fs = require('fs');
const USERS_FILE = './users.json';
let activeUsers = {}; // { socketId: { name: "User" } }
let registeredUsers = {}; // { "User": "password" }
let messageHistory = [];

// Load users
if (fs.existsSync(USERS_FILE)) {
    try {
        registeredUsers = JSON.parse(fs.readFileSync(USERS_FILE));
    } catch (e) {
        console.error("Error loading users", e);
    }
}

function saveUsers() {
    fs.writeFileSync(USERS_FILE, JSON.stringify(registeredUsers, null, 2));
}

// --- SOCKET.IO --- //
io.on('connection', (socket) => {
    let socketIp = socket.handshake.address;
    if (socketIp.startsWith('::ffff:')) socketIp = socketIp.substr(7);

    if (!isIpAllowed(socketIp)) {
        console.log(`Socket connection rejected from ${socketIp}`);
        socket.disconnect(true);
        return;
    }

    socket.on('join', (data) => {
        let username, password;
        if (typeof data === 'string') {
            username = data;
            password = '';
        } else {
            username = data.username;
            password = data.password;
        }

        const cleanName = (username || 'Usuario').trim().substring(0, 20);
        const authKey = `${cleanName}:${password}`; // Composite Identity

        // 0. Check if THIS SPECIFIC IDENTITY (Name+Pass) is already online
        const isIdentityOnline = Object.values(activeUsers).some(u => u.authKey === authKey);
        if (isIdentityOnline) {
            socket.emit('login_error', 'Esta cuenta (usuario + contraseña) ya está conectada.');
            return;
        }

        // 1. Register/Validate Identity
        // We now treat "Name:Pass" as the unique record. 
        // If it exists in JSON, good. If not, create it.
        // We no longer block "Name" if password differs. We allow "Name:Pass2".
        if (!registeredUsers[authKey]) {
            registeredUsers[authKey] = { created: Date.now() };
            saveUsers();
        }

        // Store user state
        activeUsers[socket.id] = {
            name: cleanName,
            authKey: authKey,
            ip: socketIp
        };

        socket.emit('login_success', {
            name: cleanName,
            id: socket.id
        });

        socket.broadcast.emit('message', {
            system: true,
            text: `${cleanName} se ha conectado`,
            timestamp: Date.now()
        });

        // Emit list with IPs
        io.emit('user_list', Object.entries(activeUsers).map(([id, u]) => ({
            id: id,
            name: u.name,
            ip: u.ip // Send IP to client
        })));

        socket.emit('history', messageHistory);
    });

    socket.on('chat_message', (msg) => {
        const user = activeUsers[socket.id];
        if (!user) return;

        const messageData = {
            id: Date.now() + Math.random(),
            text: msg,
            sender: user.name,
            senderId: socket.id,
            senderIp: user.ip, // Store IP
            isPrivate: false,
            timestamp: Date.now()
        };

        messageHistory.push(messageData);
        if (messageHistory.length > 50) messageHistory.shift();

        // Audit Log
        logMessage(messageData);

        io.emit('message', messageData);
    });

    socket.on('private_message', ({ targetId, text }) => {
        const user = activeUsers[socket.id];
        const target = activeUsers[targetId];

        if (!user || !target) return;

        const messageData = {
            id: Date.now() + Math.random(),
            text: text,
            sender: user.name,
            senderId: socket.id,
            senderIp: user.ip, // Store IP
            targetName: target.name, // Store name for audit
            targetId: targetId,
            targetIp: target.ip, // Store IP
            isPrivate: true,
            timestamp: Date.now()
        };

        io.to(targetId).emit('private_message', messageData);
        socket.emit('private_message', messageData);

        // Audit Log
        logMessage(messageData);
    });

    socket.on('typing', (targetId) => {
        const user = activeUsers[socket.id];
        if (user) {
            if (targetId && activeUsers[targetId]) {
                io.to(targetId).emit('typing', { user: user.name, isPrivate: true, senderId: socket.id });
            } else {
                socket.broadcast.emit('typing', { user: user.name, isPrivate: false });
            }
        }
    });

    socket.on('disconnect', () => {
        const user = activeUsers[socket.id];
        if (user) {
            socket.broadcast.emit('message', {
                system: true,
                text: `${user.name} se ha desconectado`,
                timestamp: Date.now()
            });
            delete activeUsers[socket.id];
            io.emit('user_list', Object.entries(activeUsers).map(([id, u]) => ({
                id: id,
                name: u.name,
                ip: u.ip
            })));
        }
    });
});

const LOG_FILE = './chat_logs.json';

// Helper: Append log
function logMessage(msgData) {
    let logs = [];
    if (fs.existsSync(LOG_FILE)) {
        try {
            logs = JSON.parse(fs.readFileSync(LOG_FILE));
        } catch (e) { }
    }
    logs.push(msgData);
    // Limit log size optional, but for audit we might want everything or last 10000. 
    // For simple file system, let's keep it bounded to avoid massive reads.
    if (logs.length > 5000) logs = logs.slice(-5000);
    fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
}

// --- API FOR AUDIT ---
app.get('/api/audit', (req, res) => {
    // Simple mock auth
    const auth = req.headers['x-admin-key'];
    if (auth !== 'Alexis2026') { // Hardcoded key for the user
        return res.status(403).json({ error: 'Unauthorized' });
    }

    if (fs.existsSync(LOG_FILE)) {
        res.json(JSON.parse(fs.readFileSync(LOG_FILE)));
    } else {
        res.json([]);
    }
});

const PORT = process.env.PORT || 3005;
server.listen(PORT, () => {
    console.log(`Chat-ELL Server running on port ${PORT}`);
    console.log(`Allowed IPs: 172.27.50.1 - 172.27.60.255 (+Localhost)`);
});
