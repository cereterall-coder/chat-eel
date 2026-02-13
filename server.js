const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 50 * 1024 * 1024 // 50MB
});

app.set('trust proxy', true); // Trust the network to forward real IPs

// --- CONFIGURATION --- //
// Authorized network segments are now managed dynamically via allowed_segments.json

// Helper: Check if IP is allowed
function isIpAllowed(ip) {
    if (ip.startsWith('::ffff:')) {
        ip = ip.substr(7);
    }
    console.log(`Verificando acceso para IP: ${ip}`);
    if (ip === '127.0.0.1' || ip === '::1') return true;

    // Check against authorized segments
    for (const segment of allowedSegments) {
        if (segment === ip) return true;
        if (segment.includes('-') && isIpInRange(ip, segment)) return true;
    }

    return false;
}

// --- MIDDLEWARE --- //
app.use(express.json()); // Allow JSON body
app.use((req, res, next) => {
    // Try to get real IP if behind a proxy
    let clientIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || req.socket.remoteAddress;
    if (clientIp.includes(',')) clientIp = clientIp.split(',')[0].trim();
    if (clientIp.startsWith('::ffff:')) clientIp = clientIp.substr(7);

    // DEBUG para la IP reportada
    if (clientIp === '172.27.58.98') {
        console.log('--- DEBUG IP 172.27.58.98 ---');
        console.log('Headers:', JSON.stringify(req.headers, null, 2));
        console.log('RemoteAddress:', req.socket.remoteAddress);
        console.log('X-Forwarded-For:', req.headers['x-forwarded-for']);
    }

    // Permitir acceso a paneles administrativos y APIs (estas validan la clave internamente)
    if (req.path === '/admin_portal.html' ||
        req.path === '/audit.html' ||
        req.path === '/launcher.html' ||
        req.path.startsWith('/api/') ||
        req.path === '/ip.js' ||
        req.path === '/logo.png') {
        return next();
    }

    if (isIpAllowed(clientIp)) {
        next();
    } else {
        res.status(403).send(`
            <div style="font-family: sans-serif; text-align: center; margin-top: 50px; color: #333;">
                <h1 style="color: #d32f2f;">Acceso Denegado</h1>
                <p>Su dirección IP (<strong>${clientIp}</strong>) no está autorizada para acceder a Chat-ELL.</p>
                <div style="margin-top: 20px; padding: 15px; background: #f9f9f9; display: inline-block; border-radius: 8px; border: 1px solid #ddd;">
                    <p style="color: #666; font-weight: bold; margin-bottom: 5px;">Segmentos Permitidos:</p>
                    <ul style="list-style: none; padding: 0; margin: 0; color: #888; font-family: monospace;">
                        ${allowedSegments.map(s => `<li>${s}</li>`).join('')}
                    </ul>
                </div>
                <p style="color: #999; font-size: 0.8em; mt-4">Contacte con el administrador (AMALVIVA) si cree que esto es un error.</p>
            </div>
        `);
    }
});

app.use(express.static('public'));

// Ruta dinámica para inyectar IP real en el cliente
app.get('/ip.js', (req, res) => {
    let clientIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || req.socket.remoteAddress;
    if (clientIp.includes(',')) clientIp = clientIp.split(',')[0].trim();
    if (clientIp.startsWith('::ffff:')) clientIp = clientIp.substr(7);
    res.type('application/javascript');
    res.send(`window.REAL_IP = "${clientIp}";`);
});

// ... (rest of the file until API section)

// --- API FOR AUDIT & ADMIN AUTH ---
app.post('/api/audit/login', (req, res) => {
    const { key } = req.body;
    if (key === ADMIN_KEY) {
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Clave incorrecta' });
    }
});

app.post('/api/audit/change_key', (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });

    const { newKey } = req.body;
    if (!newKey || newKey.length < 4) return res.status(400).json({ error: 'Clave insegura (min 4 chars)' });

    ADMIN_KEY = newKey;
    saveAdminKey();
    res.json({ success: true });
});

app.get('/api/audit', (req, res) => {
    const auth = req.headers['x-admin-key'];
    if (auth !== ADMIN_KEY) {
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
    if (auth !== ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });

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
const ADMIN_KEY_FILE = './admin_key.json';
const LOG_FILE = './chat_logs.json';
const SEGMENTS_FILE = './allowed_segments.json';

let activeUsers = {}; // { socketId: { name: "User" } }
let registeredUsers = {}; // { "User": "password" }
let messageHistory = [];
let ADMIN_KEY = '02855470'; // Default
let allowedSegments = [];
// ipBridge eliminado en favor de Cookies para mayor fiabilidad

// --- AUTO CLEANUP STATE ---
let activeDate = new Date().toLocaleDateString();
let lastScheduledTrigger = ''; // To avoid multiple clears within the same minute
// --------------------------

// Load users
if (fs.existsSync(USERS_FILE)) {
    try {
        registeredUsers = JSON.parse(fs.readFileSync(USERS_FILE));
    } catch (e) {
        console.error("Error loading users", e);
    }
}

// Load Admin Key
if (fs.existsSync(ADMIN_KEY_FILE)) {
    try {
        const data = JSON.parse(fs.readFileSync(ADMIN_KEY_FILE));
        if (data.key) ADMIN_KEY = data.key;
    } catch (e) {
        console.error("Error loading admin key", e);
    }
}

// Load authorized segments
if (fs.existsSync(SEGMENTS_FILE)) {
    try {
        allowedSegments = JSON.parse(fs.readFileSync(SEGMENTS_FILE));
    } catch (e) {
        console.error("Error loading segments", e);
    }
} else {
    // Default fallback
    allowedSegments = ["172.27.50.1-172.27.60.255"];
    fs.writeFileSync(SEGMENTS_FILE, JSON.stringify(allowedSegments, null, 2));
}

function saveSegments() {
    fs.writeFileSync(SEGMENTS_FILE, JSON.stringify(allowedSegments, null, 2));
}

function saveUsers() {
    fs.writeFileSync(USERS_FILE, JSON.stringify(registeredUsers, null, 2));
}

function saveAdminKey() {
    fs.writeFileSync(ADMIN_KEY_FILE, JSON.stringify({ key: ADMIN_KEY }, null, 2));
}

const GROUPS_FILE = './ip_groups.json';
let ipGroups = {};

if (fs.existsSync(GROUPS_FILE)) {
    try {
        ipGroups = JSON.parse(fs.readFileSync(GROUPS_FILE));
    } catch (e) {
        console.error("Error loading groups", e);
    }
}

function saveGroups() {
    fs.writeFileSync(GROUPS_FILE, JSON.stringify(ipGroups, null, 2));
}

const PINNED_FILE = './pinned_messages.json';
let pinnedMessages = {}; // { groupName: { messageData } }

if (fs.existsSync(PINNED_FILE)) {
    try {
        pinnedMessages = JSON.parse(fs.readFileSync(PINNED_FILE));
    } catch (e) {
        console.error("Error loading pinned messages", e);
    }
}

function savePinnedMessages() {
    fs.writeFileSync(PINNED_FILE, JSON.stringify(pinnedMessages, null, 2));
}

function isIpInRange(ip, rangeStr) {
    const parts = rangeStr.split('-');
    if (parts.length !== 2) return false;

    const startIp = parts[0].trim();
    let endIp = parts[1].trim();

    // Check if endIp is just a suffix (e.g. "10-50")
    if (!endIp.includes('.')) {
        const startParts = startIp.split('.');
        if (startParts.length !== 4) return false;
        endIp = `${startParts[0]}.${startParts[1]}.${startParts[2]}.${endIp}`;
    }

    // Convert IPs to numbers for comparison
    const ipToLong = (ipAddr) => {
        return ipAddr.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
    };

    const ipNum = ipToLong(ip);
    const startNum = ipToLong(startIp);
    const endNum = ipToLong(endIp);

    return ipNum >= startNum && ipNum <= endNum;
}

function getGroupForIp(ip) {
    for (const [groupName, entries] of Object.entries(ipGroups)) {
        for (const entry of entries) {
            if (entry === ip) return groupName;
            if (entry.includes('-') && isIpInRange(ip, entry)) return groupName;
        }
    }
    return 'General'; // Default group if not found
}

// --- API FOR GROUPS ---
app.get('/api/groups', (req, res) => {
    if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });
    res.json(ipGroups);
});

app.post('/api/groups', (req, res) => {
    if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });
    const { group, action, ip } = req.body;

    if (!group) return res.status(400).json({ error: 'Group name required' });

    // Create Group
    if (action === 'create') {
        if (ipGroups[group]) return res.status(400).json({ error: 'Group exists' });
        ipGroups[group] = [];
        saveGroups();
        return res.json({ success: true, groups: ipGroups });
    }

    // Add IP
    if (action === 'add_ip') {
        if (!ipGroups[group]) return res.status(404).json({ error: 'Group not found' });
        if (ipGroups[group].includes(ip)) return res.json({ success: true }); // already exists
        ipGroups[group].push(ip);
        saveGroups();
        return res.json({ success: true, groups: ipGroups });
    }

    // Remove IP
    if (action === 'remove_ip') {
        if (!ipGroups[group]) return res.status(404).json({ error: 'Group not found' });
        ipGroups[group] = ipGroups[group].filter(i => i !== ip);
        saveGroups();
        return res.json({ success: true, groups: ipGroups });
    }

    // Delete Group
    if (action === 'delete_group') {
        delete ipGroups[group];
        saveGroups();
        return res.json({ success: true, groups: ipGroups });
    }

    // Clear Group History
    if (action === 'clear_history') {
        if (!ipGroups[group]) return res.status(404).json({ error: 'Group not found' });

        // Remove public messages of this group from history
        const initialLen = messageHistory.length;
        messageHistory = messageHistory.filter(m => m.group !== group || m.isPrivate);

        // Notify clients in that group to clear screen
        io.to(group).emit('history_clear');

        return res.json({ success: true, removed: initialLen - messageHistory.length });
    }

    res.status(400).json({ error: 'Invalid action' });
});

// --- API FOR AUTHORIZED SEGMENTS ---
app.get('/api/segments', (req, res) => {
    if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });
    res.json(allowedSegments);
});

app.post('/api/segments', (req, res) => {
    if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });
    const { action, segment } = req.body;

    if (action === 'add') {
        if (!segment) return res.status(400).json({ error: 'Segment required' });
        if (allowedSegments.includes(segment)) return res.json({ success: true, segments: allowedSegments });
        allowedSegments.push(segment);
        saveSegments();
        return res.json({ success: true, segments: allowedSegments });
    }

    if (action === 'remove') {
        allowedSegments = allowedSegments.filter(s => s !== segment);
        saveSegments();
        return res.json({ success: true, segments: allowedSegments });
    }

    res.status(400).json({ error: 'Invalid action' });
});

// --- API FOR USER MANAGEMENT ---
app.get('/api/users', (req, res) => {
    if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });

    // Return list of usernames. 
    // Keys are "Username:Password". We just want "Username".
    const users = Object.keys(registeredUsers).map(key => {
        const parts = key.split(':');
        // Handle cases where password might contain ':'? 
        // The join logic `key = name:pass`.
        // We can safely assume last part is pass? Or first part is name?
        // `cleanName` logic in join: `trim().substring(0, 20)`.
        // Let's assume first part is name.
        // Or better, just return the full keys and let client parse, 
        // OR return objects { username: ... }
        // Let's iterate and extract username.
        // Note: ':' usage in username was not strictly blocked but `cleanName` is just trim/substring.
        // It's better to store just names.
        // If "Alexis:123", part[0] = Alexis.
        return parts[0];
    });
    // Deduplicate in case of weirdness (though keys are unique strings)
    const uniqueUsers = [...new Set(users)];
    res.json(uniqueUsers);
});

app.post('/api/users/update_password', (req, res) => {
    if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });
    const { username, newPassword } = req.body;

    if (!username || !newPassword) return res.status(400).json({ error: 'Missing params' });

    // Find existing entry
    const existingKey = Object.keys(registeredUsers).find(k => k.startsWith(username + ':'));

    // If not found, maybe create it? Or error?
    // Let's error if user doesn't exist, strictly speaking. 
    // BUT, the system creates users on fly. So maybe valid to create new?
    // User asked "Change Key", implies existing.

    if (!existingKey) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const oldData = registeredUsers[existingKey];
    const newKey = `${username}:${newPassword}`;

    // Update
    delete registeredUsers[existingKey];
    registeredUsers[newKey] = oldData;
    saveUsers();

    // Optional: Disconnect active user?
    // const activeSocketId = Object.keys(activeUsers).find(id => activeUsers[id].name === username);
    // if (activeSocketId) {
    //    io.sockets.sockets.get(activeSocketId)?.disconnect(true);
    // }

    res.json({ success: true });
});

// --- SOCKET.IO --- //
io.on('connection', (socket) => {
    let socketIp = socket.handshake.query.realIp || socket.handshake.headers['x-forwarded-for'] || socket.handshake.headers['x-real-ip'] || socket.handshake.address;
    if (socketIp.includes(',')) socketIp = socketIp.split(',')[0].trim();
    if (socketIp.startsWith('::ffff:')) socketIp = socketIp.substr(7);

    if (socket.handshake.query.realIp) {
        // Solo log si la IP es diferente a la de conexión (Proxy detectado)
        if (socket.handshake.query.realIp !== socket.handshake.address.replace('::ffff:', '')) {
            console.log(`[IDENTIFICACIÓN] Cliente identificado vía Query: ${socketIp} (Conexión desde ${socket.handshake.address})`);
        }
    }

    if (!isIpAllowed(socketIp)) {
        console.log(`Socket connection rejected from ${socketIp}`);
        socket.disconnect(true);
        return;
    }

    // --- MONITOR AUTH ---
    socket.on('monitor_auth', (key) => {
        if (key === ADMIN_KEY) {
            // Register as hidden user
            activeUsers[socket.id] = {
                name: 'Soporte',
                authKey: 'monitor-key',
                ip: socketIp,
                group: 'MONITOR',
                hidden: true,
                isSupervisor: true
            };
            socket.join('monitors');
            socket.emit('monitor_auth_result', { success: true });

            // Send immediate state
            socket.emit('monitor_update', activeUsers);
        } else {
            socket.emit('monitor_auth_result', { success: false, error: 'Clave incorrecta' });
        }
    });

    // Helper to notify monitors
    function broadcastMonitorUpdate() {
        io.to('monitors').emit('monitor_update', activeUsers);
    }

    socket.on('monitor_message', (payload) => {
        // Wrapper for sending private messages as monitor
        const user = activeUsers[socket.id];
        if (!user || user.name !== 'Soporte') return;

        const targetId = payload.targetId;
        const target = activeUsers[targetId];

        if (!target) return;

        const messageData = {
            id: Date.now() + Math.random(),
            text: payload.text,
            sender: user.name,
            senderId: socket.id,
            targetName: target.name,
            targetId: targetId,
            isPrivate: true,
            timestamp: Date.now()
        };

        io.to(targetId).emit('private_message', messageData);
        // No need to echo back to socket, client handles it
        logMessage(messageData);
    });

    socket.on('monitor_broadcast', (payload) => {
        const user = activeUsers[socket.id];
        if (!user || user.name !== 'Soporte') return;

        const group = payload.group;
        if (!group) return;

        if (group === 'ALL') {
            const messageData = {
                id: Date.now() + Math.random(),
                text: payload.text,
                sender: user.name,
                senderId: socket.id,
                group: 'GLOBAL',
                isPrivate: false,
                timestamp: Date.now()
            };
            messageHistory.push(messageData);
            if (messageHistory.length > 100) messageHistory.shift();
            logMessage(messageData);
            io.emit('message', messageData); // Broadcast to everyone
        } else {
            const messageData = {
                id: Date.now() + Math.random(),
                text: payload.text,
                sender: user.name,
                senderId: socket.id,
                group: group,
                isPrivate: false,
                timestamp: Date.now()
            };
            messageHistory.push(messageData);
            if (messageHistory.length > 100) messageHistory.shift();
            logMessage(messageData);
            io.to(group).emit('message', messageData);
        }
    });

    socket.on('join', (data) => {
        let username, password;
        if (typeof data === 'string') {
            username = data;
            password = '';
        } else {
            username = data.username;
            password = data.password;
        }

        // --- NEW DAY CHECK ---
        const today = new Date().toLocaleDateString();
        if (today !== activeDate) {
            activeDate = today;
            console.log(`[New Day] Primer ingreso del día detected (${today}). Limpiando EEL...`);
            clearGroupHistory('EEL'); // Reset EEL on first login of the day
        }
        // ---------------------

        const cleanName = (username || 'Usuario').trim().substring(0, 20);
        const authKey = `${cleanName}:${password}`;

        // Supervisor Check: Username is "SUPERVISOR" AND Password starts/ends with '@'
        const isSupervisor = (cleanName.toUpperCase() === 'SUPERVISOR' && password && password.length > 2 && password.startsWith('@') && password.endsWith('@'));

        if (cleanName.toUpperCase() === 'SUPERVISOR' && !isSupervisor) {
            socket.emit('login_error', '🔒 Nombre reservado. Para usar "SUPERVISOR" debe tener la credencial de seguridad correcta.');
            return;
        }

        const isIdentityOnline = Object.values(activeUsers).some(u => u.authKey === authKey);
        if (isIdentityOnline) {
            socket.emit('login_error', 'Esta cuenta (usuario + contraseña) ya está conectada.');
            return;
        }

        if (!registeredUsers[authKey]) {
            registeredUsers[authKey] = { created: Date.now() };
            saveUsers();
        }

        // Determine Group
        const userGroup = getGroupForIp(socketIp);
        socket.join(userGroup); // Join socket.io room

        activeUsers[socket.id] = {
            name: cleanName,
            authKey: authKey,
            ip: socketIp,
            group: userGroup,
            isSupervisor: isSupervisor // Store role
        };

        socket.emit('login_success', {
            name: cleanName,
            id: socket.id,
            group: userGroup,
            isSupervisor: isSupervisor
        });

        // Broadcast ONLY to group
        socket.to(userGroup).emit('message', {
            system: true,
            text: `${cleanName} se ha conectado a la sala ${userGroup}`,
            timestamp: Date.now()
        });

        // Helper to emit user list for specific room
        function broadcastGroupUserList(groupName) {
            const usersInGroup = Object.entries(activeUsers)
                .filter(([_, u]) => u.group === groupName && !u.hidden) // Filter hidden monitors
                .map(([id, u]) => ({
                    id: id,
                    name: u.name,
                    ip: u.ip,
                    isSupervisor: u.isSupervisor // Needed for permissions
                }));
            io.to(groupName).emit('user_list', usersInGroup);
        }



        broadcastGroupUserList(userGroup);

        // Send group-filtered history (Newest first for UI so we reverse it)
        const groupHistory = messageHistory.filter(m => m.group === userGroup && !m.isPrivate);
        socket.emit('history', groupHistory);

        // Send Pinned Message
        if (pinnedMessages[userGroup]) {
            socket.emit('pinned_message_update', pinnedMessages[userGroup]);
        }

        broadcastMonitorUpdate(); // Notify monitors
    });

    socket.on('chat_message', (payload) => {
        const user = activeUsers[socket.id];
        if (!user) return;

        // payload can be string (old) or object { text, image, ... }
        const text = (typeof payload === 'string') ? payload : payload.text;
        const image = payload.image || null;

        // RESTRICTION: Block images for EEL group
        // RESTRICTION: In EEL, only Supervisor can broadcast images
        if (image && user.group === 'EEL' && !user.isSupervisor) {
            socket.emit('message', {
                system: true,
                text: '🚫 Solo el SUPERVISOR puede enviar imágenes a este grupo.',
                timestamp: Date.now()
            });
            return;
        }

        const messageData = {
            id: Date.now() + Math.random(),
            text: text,
            image: image,
            sender: user.name,
            senderId: socket.id,
            senderIp: user.ip,
            group: user.group,
            isPrivate: false,
            timestamp: Date.now()
        };

        messageHistory.push(messageData);
        if (messageHistory.length > 50) messageHistory.shift(); // Keep limit small if storing images

        logMessage(messageData);

        // Emit only to group
        io.to(user.group).emit('message', messageData);

        // Notify Supervisors
        const supervisorsInGroup = Object.values(activeUsers).filter(u => u.group === user.group && u.isSupervisor && u.authKey !== user.authKey);
        supervisorsInGroup.forEach(sup => {
            const supSocketId = Object.keys(activeUsers).find(key => activeUsers[key] === sup);
            if (supSocketId) {
                io.to(supSocketId).emit('supervisor_alert', {
                    sender: user.name,
                    text: text || '📷 Imagen adjunta', // Fallback details
                    senderId: socket.id,
                    isPrivate: false
                });
            }
        });
    });

    socket.on('private_message', (payload) => {
        // payload: { targetId, text, image, ... }
        const user = activeUsers[socket.id];
        const targetId = payload.targetId;
        const target = activeUsers[targetId];

        if (!user || !target) return;

        const text = payload.text;
        const image = payload.image || null;

        // RESTRICTION: Block images for EEL group in private too
        // RESTRICTION: In EEL, users can only send images to SUPERVISOR
        // Supervisors can send to anyone.
        if (image && user.group === 'EEL' && !user.isSupervisor) {
            if (!target.isSupervisor) {
                socket.emit('message', {
                    system: true,
                    text: '🚫 Tus imágenes solo pueden enviarse al SUPERVISOR.',
                    timestamp: Date.now()
                });
                return;
            }
        }

        const messageData = {
            id: Date.now() + Math.random(),
            text: text,
            image: image,
            sender: user.name,
            senderId: socket.id,
            senderIp: user.ip,
            targetName: target.name,
            targetId: targetId,
            targetIp: target.ip,
            isPrivate: true,
            timestamp: Date.now()
        };

        if (target.isSupervisor) {
            io.to(targetId).emit('supervisor_alert', {
                sender: user.name,
                text: text || '📷 Imagen adjunta',
                senderId: user.id || socket.id,
                isPrivate: true
            });
        }

        io.to(targetId).emit('private_message', messageData);
        socket.emit('private_message', messageData);

        logMessage(messageData);
    });

    socket.on('typing', (targetId) => {
        const user = activeUsers[socket.id];
        if (user) {
            if (targetId && activeUsers[targetId]) {
                io.to(targetId).emit('typing', { user: user.name, isPrivate: true, senderId: socket.id });
            } else {
                // Broadcast typing only to group
                socket.to(user.group).emit('typing', { user: user.name, isPrivate: false });
            }
        }
    });

    socket.on('pin_message', (msgData) => {
        const user = activeUsers[socket.id];
        // Only Supervisor can pin
        if (!user || user.group === 'EEL' && !user.isSupervisor) {
            // Let's assume only Supervisors can pin generally, or maybe check group logic?
            // User just said "enable option", but usually this is an admin feature.
            // Given the context of restrictions in EEL, I'll stick to Supervisor-only for safety 
            // OR allow anyone in non-restricted groups? 
            // Let's enforce Supervisor check for now as safer default, or at least for EEL.
            // "monitor_auth" users are supervisors.
            if (!user.isSupervisor) return;
        }

        // Save Pinned Message for the group
        pinnedMessages[user.group] = msgData;
        savePinnedMessages();

        // Broadcast to Group
        io.to(user.group).emit('pinned_message_update', msgData);

        // Broadcast to Supervisors of that group? Done via group emit.
    });

    socket.on('unpin_message', () => {
        const user = activeUsers[socket.id];
        if (!user || !user.isSupervisor) return;

        if (pinnedMessages[user.group]) {
            delete pinnedMessages[user.group];
            savePinnedMessages();
            io.to(user.group).emit('pinned_message_update', null);
        }
    });

    socket.on('disconnect', () => {
        const user = activeUsers[socket.id];
        if (user) {
            const group = user.group;

            socket.to(group).emit('message', {
                system: true,
                text: `${user.name} se ha desconectado`,
                timestamp: Date.now()
            });

            delete activeUsers[socket.id];

            // Re-calc list for that group
            const usersInGroup = Object.entries(activeUsers)
                .filter(([_, u]) => u.group === group)
                .map(([id, u]) => ({
                    id: id,
                    name: u.name,
                    ip: u.ip
                }));

            io.to(group).emit('user_list', usersInGroup);
            broadcastMonitorUpdate(); // Notify monitors
        }
    });
});



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




// --- SCHEDULED CLEANUP LOGIC ---
function clearGroupHistory(groupName) {
    // 1. Filter out messages of this group from memory
    messageHistory = messageHistory.filter(m => m.group !== groupName);

    // 2. Notify active users in that group to wipe their screens
    // We send an empty history array which client renders as "zero messages"
    const socketsInGroup = Object.keys(activeUsers).filter(id => activeUsers[id].group === groupName);

    socketsInGroup.forEach(targetId => {
        io.to(targetId).emit('history', []); // Clear UI
        io.to(targetId).emit('message', {
            system: true,
            text: '🧹 Mantenimiento: El historial ha sido reiniciado automáticamente.',
            timestamp: Date.now()
        });
    });

    console.log(`[Auto-Clean] Historial del grupo ${groupName} eliminado.`);
}

// Check every minute
setInterval(() => {
    const now = new Date();
    const headers = now.getHours().toString().padStart(2, '0') + ':' + now.getMinutes().toString().padStart(2, '0');

    // Triggers: 14:05 (02:05 PM) and 22:00 (10:00 PM)
    if ((headers === '14:05' || headers === '22:00') && lastScheduledTrigger !== headers) {
        lastScheduledTrigger = headers;
        clearGroupHistory('EEL');
    }
}, 30000); // Check every 30s


const PORT = process.env.PORT || 3005;
server.listen(PORT, () => {
    console.log(`CHAT-RALL Server running on port ${PORT}`);
    console.log(`Allowed IPs: 172.27.50.1 - 172.27.60.255 (+Localhost)`);
});
