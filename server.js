const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 50 * 1024 * 1024 // 50MB
});

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
app.use(express.static('public'));
app.use(express.json());

// IP Middleware: Open for testing
app.use((req, res, next) => {
    next();
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 CHAT-ELL ONLINE en el puerto ${PORT}`);
    console.log(`Acceso local: http://localhost:${PORT}`);
});

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

const bcrypt = require('bcryptjs');
const fs = require('fs');
const USERS_FILE = './users.json';
const PENDING_FILE = './pending_users.json';
const ADMIN_KEY_FILE = './admin_key.json';
const LOG_FILE = './chat_logs.json';
const GROUPS_FILE = './ip_groups.json';
const PINNED_FILE = './pinned_messages.json';

let activeUsers = {}; // { socketId: { name, username, phone, group, ip, isSupervisor } }
let registeredUsers = {}; // { username: { passwordHash, phone, office, status } }
let pendingUsers = {}; // { username: { phone, office, ip, code, status: 'waiting' } }
let messageHistory = [];
let ADMIN_KEY = '02855470';

// Load data
if (fs.existsSync(USERS_FILE)) {
    try { registeredUsers = JSON.parse(fs.readFileSync(USERS_FILE)); } catch (e) { }
}
if (fs.existsSync(PENDING_FILE)) {
    try { pendingUsers = JSON.parse(fs.readFileSync(PENDING_FILE)); } catch (e) { }
}

function saveUsers() { fs.writeFileSync(USERS_FILE, JSON.stringify(registeredUsers, null, 2)); }
function savePending() { fs.writeFileSync(PENDING_FILE, JSON.stringify(pendingUsers, null, 2)); }

// Load History
if (fs.existsSync(LOG_FILE)) {
    try {
        messageHistory = JSON.parse(fs.readFileSync(LOG_FILE));
        // Keep only last 200 for memory safety
        if (messageHistory.length > 200) messageHistory = messageHistory.slice(-200);
    } catch (e) { }
}

// --- API FOR REGISTRATION FLOW ---

// 1. User requests registration
app.post('/api/auth/register', (req, res) => {
    const { username, fullName, phone, office } = req.body;
    const clientIp = req.ip || req.socket.remoteAddress;

    if (!username || !phone) return res.status(400).json({ error: 'Usuario y Teléfono obligatorios' });

    // Check if user exists (case-insensitive)
    const exists = Object.keys(registeredUsers).some(k => k.toLowerCase() === username.toLowerCase());
    if (exists) return res.status(400).json({ error: 'El nombre de usuario ya está registrado' });

    pendingUsers[username] = {
        fullName,
        phone,
        office,
        ip: clientIp,
        timestamp: Date.now(),
        status: 'pending_approval'
    };
    savePending();
    res.json({ success: true, message: 'Solicitud enviada. Contacte al administrador.' });
});

// 2. Admin views pending requests
app.get('/api/admin/pending', (req, res) => {
    if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });
    res.json(pendingUsers);
});

// 3. Admin approves and sends Code (This generates a code for the user)
app.post('/api/admin/approve', (req, res) => {
    if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });
    const { username } = req.body;
    if (!pendingUsers[username]) return res.status(404).json({ error: 'No encontrado' });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    pendingUsers[username].code = code;
    pendingUsers[username].status = 'approved_waiting_code';
    savePending();

    // Generate WhatsApp Link
    const phone = pendingUsers[username].phone;
    const msg = encodeURIComponent(`Hola ${pendingUsers[username].fullName}, tu código de acceso para CHAT-ELL es: *${code}*. Ingrésalo para activar tu cuenta.`);
    const waLink = `https://wa.me/51${phone}?text=${msg}`;

    res.json({ success: true, code, waLink });
});

// 4. User activates account with code and sets password
app.post('/api/auth/activate', async (req, res) => {
    const { username, code, password } = req.body;

    if (!pendingUsers[username] || pendingUsers[username].code !== code) {
        return res.status(400).json({ error: 'Código de activación incorrecto' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    registeredUsers[username] = {
        passwordHash,
        phone: pendingUsers[username].phone,
        office: pendingUsers[username].office,
        fullName: pendingUsers[username].fullName,
        created: Date.now()
    };

    delete pendingUsers[username];
    saveUsers();
    savePending();

    res.json({ success: true, message: 'Cuenta activada correctamente' });
});

// 5. Normal Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Usuario y Contraseña requeridos' });

        const normalizedInput = String(username).toLowerCase();
        const regUsername = Object.keys(registeredUsers).find(k => k.toLowerCase() === normalizedInput);
        const user = regUsername ? registeredUsers[regUsername] : null;

        if (!user) {
            console.log(`[LOGIN] Usuario no encontrado: ${username}`);
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }

        // Check if password exists
        if (!user.passwordHash) {
            console.error(`[LOGIN] Error crítico: El usuario ${username} no tiene contraseña hash guardada.`);
            return res.status(500).json({ error: 'Error interno de cuenta. Contacte al administrador.' });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            console.log(`[LOGIN] Contraseña incorrecta para: ${username}`);
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        console.log(`[LOGIN] Éxito: ${username} ha entrado.`);
        res.json({
            success: true,
            user: {
                username,
                fullName: user.fullName,
                office: user.office,
                isSupervisor: username.toUpperCase() === 'SUPERVISOR'
            }
        });
    } catch (err) {
        console.error('[LOGIN ERROR]', err);
        res.status(500).json({ error: 'Error interno del servidor. Intente de nuevo.' });
    }
});



let ipGroups = {};
if (fs.existsSync(GROUPS_FILE)) {
    try { ipGroups = JSON.parse(fs.readFileSync(GROUPS_FILE)); } catch (e) { }
}

function saveGroups() { fs.writeFileSync(GROUPS_FILE, JSON.stringify(ipGroups, null, 2)); }

let pinnedMessages = {};
if (fs.existsSync(PINNED_FILE)) {
    try { pinnedMessages = JSON.parse(fs.readFileSync(PINNED_FILE)); } catch (e) { }
}

function savePinnedMessages() { fs.writeFileSync(PINNED_FILE, JSON.stringify(pinnedMessages, null, 2)); }


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
    let socketIp = socket.handshake.address;
    if (socketIp.startsWith('::ffff:')) socketIp = socketIp.substr(7);

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

        const messageData = {
            id: Date.now() + Math.random(),
            text: payload.text,
            sender: user.name, // 'Soporte'
            senderId: socket.id,
            group: group,
            isPrivate: false,
            timestamp: Date.now()
        };

        messageHistory.push(messageData);
        if (messageHistory.length > 50) messageHistory.shift();
        logMessage(messageData);

        io.to(group).emit('message', messageData);
    });

    socket.on('join', (data) => {
        const { username } = data;
        const normalizedInput = String(username).toLowerCase();

        // Find user case-insensitively
        const regUsername = Object.keys(registeredUsers).find(k => k.toLowerCase() === normalizedInput);
        const regUser = regUsername ? registeredUsers[regUsername] : null;

        if (!regUser) {
            console.log(`[JOIN ERROR] Identity not found for: ${username}`);
            socket.emit('login_error', '🔒 Error de identidad. Vuelva a iniciar sesión.');
            return;
        }

        // --- NEW DAY CHECK ---
        const today = new Date().toLocaleDateString();
        // (Existing new day logic can stay or be simplified)

        // Allowing multiple sessions for the same user (useful for testing and multi-device)
        /*
        const isIdentityOnline = Object.values(activeUsers).some(u => String(u.username).toLowerCase() === normalizedInput);
        if (isIdentityOnline) {
            const oldSocketId = Object.keys(activeUsers).find(id => String(activeUsers[id].username).toLowerCase() === normalizedInput);
            if (oldSocketId) {
                io.sockets.sockets.get(oldSocketId)?.disconnect(true);
            }
        }
        */

        const userGroup = regUser.office || 'General';
        socket.join('GLOBAL');
        socket.join(userGroup);
        socket.join(String(username).toLowerCase()); // JOIN LOWERCASE ROOM

        activeUsers[socket.id] = {
            name: regUser.fullName || username,
            username: username,
            phone: regUser.phone || '',
            office: regUser.office || 'General',
            ip: socketIp,
            group: userGroup,
            isSupervisor: username.toUpperCase() === 'SUPERVISOR'
        };

        socket.emit('login_success', {
            username: activeUsers[socket.id].username,
            name: activeUsers[socket.id].name,
            id: socket.id,
            group: userGroup,
            isSupervisor: activeUsers[socket.id].isSupervisor,
            ip: activeUsers[socket.id].ip,
            phone: activeUsers[socket.id].phone
        });

        // Broadcast to EVERYONE that someone is online (FULL LIST)
        const fullUserList = Object.entries(activeUsers).map(([id, u]) => ({
            id,
            username: u.username,
            name: u.name,
            office: u.office,
            ip: u.ip,
            phone: u.phone,
            isSupervisor: u.isSupervisor
        }));
        io.emit('user_list', fullUserList);

        // SEND HISTORY: Global messages + Private messages where this user is involved
        const userHistory = messageHistory.filter(m => {
            if (!m.isPrivate) return true; // Global
            const me = String(username).toLowerCase();
            const sender = String(m.username).toLowerCase();
            const target = String(m.targetUsername).toLowerCase();
            return sender === me || target === me;
        });
        socket.emit('history', userHistory);
    });

    socket.on('chat_message', (payload) => {
        const user = activeUsers[socket.id];
        if (!user) return;
        console.log(`[EVENT] chat_message from ${user.username}`);

        const text = (typeof payload === 'string') ? payload : payload.text;
        const image = payload.image || null;

        const messageData = {
            id: String(Date.now() + Math.random()),
            text: text,
            image: image,
            sender: user.name,
            username: user.username,
            senderId: socket.id,
            office: user.office,
            phone: user.phone,
            timestamp: Date.now()
            // No forced group here, we can have 1:1 or specific channels later
        };

        // For now, send to GLOBAL room
        io.to('GLOBAL').emit('message', messageData);
        messageHistory.push(messageData);
        if (messageHistory.length > 200) messageHistory.shift();
        logMessage(messageData);
    });


    socket.on('private_message', (payload) => {
        const user = activeUsers[socket.id];
        const targetUsername = payload.targetId; // This is the username from client

        // Find ANY active session for this username to get their profile data
        const target = Object.values(activeUsers).find(u => String(u.username).toLowerCase() === String(targetUsername).toLowerCase());

        if (!user || !target) {
            console.log(`[PRIVATE ERROR] From ${user ? user.username : 'UNK'} to ${targetUsername}. Target found: ${!!target}`);
            return;
        }

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
            id: String(Date.now() + Math.random()),
            text: text,
            image: image,
            sender: user.name,
            username: user.username,
            senderId: socket.id,
            senderIp: user.ip,
            targetName: target.name,
            targetUsername: target.username,
            isPrivate: true,
            timestamp: Date.now()
        };
        console.log(`[MSG] Private from ${user.username} to ${target.username}: ${text ? text.substring(0, 20) : 'IMAGE'}`);

        if (target.isSupervisor) {
            io.to(String(target.username).toLowerCase()).emit('supervisor_alert', {
                sender: user.name,
                text: text || '📷 Imagen adjunta',
                senderId: String(user.username).toLowerCase(),
                isPrivate: true
            });
        }

        io.to(String(target.username).toLowerCase()).emit('private_message', messageData);
        io.to(String(user.username).toLowerCase()).emit('private_message', messageData);

        messageHistory.push(messageData);
        if (messageHistory.length > 200) messageHistory.shift();
        logMessage(messageData);
    });

    socket.on('typing', (targetUsername) => {
        const user = activeUsers[socket.id];
        if (user) {
            if (targetUsername) {
                io.to(String(targetUsername).toLowerCase()).emit('typing', { user: user.name, isPrivate: true, senderId: String(user.username).toLowerCase() });
            } else {
                io.to(user.group).emit('typing', { user: user.name, isPrivate: false });
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

    socket.on('delete_message', (msgId) => {
        const user = activeUsers[socket.id];
        if (!user) return;

        const idToSearch = String(msgId);

        // Find message in history
        const msgIndex = messageHistory.findIndex(m => String(m.id) === idToSearch);
        if (msgIndex !== -1) {
            const msg = messageHistory[msgIndex];

            // SECURITY: Only sender can delete, and only if from today
            const isOwner = msg.username === user.username;
            const isToday = new Date(msg.timestamp).toDateString() === new Date().toDateString();

            if (isOwner && isToday) {
                messageHistory.splice(msgIndex, 1);
                io.emit('message_deleted', msgId);

                // Also update persistent log
                if (fs.existsSync(LOG_FILE)) {
                    try {
                        let logs = JSON.parse(fs.readFileSync(LOG_FILE));
                        logs = logs.filter(l => String(l.id) !== idToSearch);
                        fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
                    } catch (e) { }
                }
            }
        } else {
            io.emit('message_deleted', msgId);
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

            // Re-calc FULL list for everyone
            const fullUserList = Object.entries(activeUsers).map(([id, u]) => ({
                id,
                username: u.username,
                name: u.name,
                office: u.office,
                ip: u.ip,
                phone: u.phone,
                isSupervisor: u.isSupervisor
            }));

            io.emit('user_list', fullUserList);
            broadcastMonitorUpdate();
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

