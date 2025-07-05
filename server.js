const express = require('express');
const fs = require('fs');
const path = require('path');
const fileUpload = require('express-fileupload');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();
const helmet = require('helmet');
const app = express();
const PORT = 3000;

// Enable CORS for all routes
app.use(cors());
app.use(helmet());

// Enable file upload and session
app.use(fileUpload());
app.use(session({
    secret: 'suntechpower_secret',
    resave: false,
    saveUninitialized: true
}));

// Simple in-memory rate limiter for login attempts
const loginAttempts = {};
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes

// --- Admin Action Logging to File ---
const adminLogPath = path.join(__dirname, 'assets/data/admin-log.json');
async function appendAdminLog(entry) {
    let logs = [];
    try {
        logs = JSON.parse(await fs.promises.readFile(adminLogPath, 'utf8'));
    } catch {}
    logs.unshift(entry); // newest first
    if (logs.length > 100) logs = logs.slice(0, 100); // keep last 100
    await fs.promises.writeFile(adminLogPath, JSON.stringify(logs, null, 2));
}
function logAdminAction(action, details = {}) {
    const timestamp = new Date().toISOString();
    const entry = { timestamp, action, ...details };
    console.log(`[ADMIN ACTION] ${timestamp} | ${action} |`, details);
    appendAdminLog(entry);
}

// Admin login (multi-user)
app.post('/admin/login', express.json(), async (req, res) => {
    const ip = req.ip;
    const now = Date.now();
    if (!loginAttempts[ip]) loginAttempts[ip] = [];
    loginAttempts[ip] = loginAttempts[ip].filter(ts => now - ts < WINDOW_MS);
    if (loginAttempts[ip].length >= MAX_ATTEMPTS) {
        return res.status(429).json({ success: false, message: 'Too many login attempts. Please try again later.' });
    }
    loginAttempts[ip].push(now);
    const { username, password } = req.body;
    console.log('[DEBUG] Admin login attempt. Username:', username);
    const admins = await getAdmins();
    const user = admins.find(a => a.username === username);
    if (user && await bcrypt.compare(password, user.passwordHash)) {
        req.session.isAdmin = true;
        req.session.adminUser = username;
        logAdminAction('LOGIN_SUCCESS', { ip, username });
        res.json({ success: true });
    } else {
        logAdminAction('LOGIN_FAIL', { ip, username });
        res.status(401).json({ success: false, message: 'Invalid username or password' });
    }
});

// Admin logout
app.post('/admin/logout', (req, res) => {
    logAdminAction('LOGOUT', { ip: req.ip });
    req.session.destroy(() => res.json({ success: true }));
});

// Middleware to protect admin routes
function requireAdmin(req, res, next) {
    if (req.session && req.session.isAdmin) {
        req.adminUser = req.session.adminUser;
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
}

// Log every incoming request for debugging
app.use((req, res, next) => {
    console.log(`[DEBUG] Incoming request: ${req.method} ${req.url}`);
    next();
});

// Serve static files
app.use(express.static(path.join(__dirname)));

// API endpoint to list images in completed projects folder
app.get('/api/completed-projects', (req, res) => {
    const jsonPath = path.join(__dirname, 'assets/images/completed/completed-projects.json');
    if (fs.existsSync(jsonPath)) {
        // Serve JSON file if it exists
        fs.readFile(jsonPath, 'utf8', (err, data) => {
            if (err) return res.status(500).json({ error: 'Unable to read completed-projects.json' });
            try {
                const arr = JSON.parse(data);
                res.json(arr);
            } catch (e) {
                res.status(500).json({ error: 'Invalid JSON format in completed-projects.json' });
            }
        });
    } else {
        // Fallback: list images in folder
        const dir = path.join(__dirname, 'assets/images/completed');
        fs.readdir(dir, (err, files) => {
            if (err) return res.status(500).json({ error: 'Unable to read images folder' });
            const images = files.filter(f => /\.(jpg|jpeg|png|gif|webp)$/i.test(f)).map(f => ({
                src: `/assets/images/completed/${f}`,
                title: f.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' '),
                desc: ''
            }));
            res.json(images);
        });
    }
});

// Helper: validate project object
function isValidProject(obj) {
    return obj && typeof obj.src === 'string' && obj.src.length > 0 &&
        typeof obj.title === 'string' && obj.title.length > 0 &&
        typeof obj.desc === 'string' && obj.desc.length > 0;
}

// Image upload endpoint (now supports folder param for products/services)
app.post('/admin/upload', requireAdmin, (req, res) => {
    const folder = req.query.folder || 'completed';
    const allowed = ['completed', 'products', 'services'];
    if (!allowed.includes(folder)) return res.status(400).json({ error: 'Invalid folder' });
    if (!req.files || !req.files.image) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    const image = req.files.image;
    // Validate file type
    if (!/\.(jpg|jpeg|png|gif|webp)$/i.test(image.name)) {
        return res.status(400).json({ error: 'Invalid file type' });
    }
    const uploadPath = path.join(__dirname, 'assets/images', folder, image.name);
    image.mv(uploadPath, async err => {
        if (err) return res.status(500).json({ error: 'Upload failed' });
        await updateAnalytics('uploads');
        logAdminAction('UPLOAD_IMAGE', { ip: req.ip, folder, filename: image.name });
        res.json({ success: true, filename: image.name });
    });
});

// CRUD for completed-projects.json
const jsonPath = path.join(__dirname, 'assets/images/completed/completed-projects.json');

// Update (replace) the entire projects list
app.post('/admin/projects', requireAdmin, express.json(), (req, res) => {
    if (!Array.isArray(req.body) || !req.body.every(isValidProject)) {
        return res.status(400).json({ error: 'Invalid project data' });
    }
    fs.writeFile(jsonPath, JSON.stringify(req.body, null, 2), err => {
        if (err) return res.status(500).json({ error: 'Failed to save projects' });
        logAdminAction('REPLACE_PROJECTS', { ip: req.ip, count: req.body.length });
        res.json({ success: true });
    });
});

// Get all projects
app.get('/admin/projects', requireAdmin, (req, res) => {
    fs.readFile(jsonPath, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Unable to read completed-projects.json' });
        try {
            const arr = JSON.parse(data);
            res.json(arr);
        } catch (e) {
            res.status(500).json({ error: 'Invalid JSON format in completed-projects.json' });
        }
    });
});

// Update a project by index
app.put('/admin/projects/:index', requireAdmin, express.json(), (req, res) => {
    const idx = parseInt(req.params.index, 10);
    if (!isValidProject(req.body)) {
        return res.status(400).json({ error: 'Invalid project data' });
    }
    fs.readFile(jsonPath, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Unable to read completed-projects.json' });
        let arr;
        try {
            arr = JSON.parse(data);
        } catch (e) {
            return res.status(500).json({ error: 'Invalid JSON format in completed-projects.json' });
        }
        if (idx < 0 || idx >= arr.length) return res.status(400).json({ error: 'Invalid index' });
        arr[idx] = req.body;
        fs.writeFile(jsonPath, JSON.stringify(arr, null, 2), err2 => {
            if (err2) return res.status(500).json({ error: 'Failed to update project' });
            logAdminAction('UPDATE_PROJECT', { ip: req.ip, index: idx });
            res.json({ success: true });
        });
    });
});

// Delete a project by index (and its image file)
app.delete('/admin/projects/:index', requireAdmin, (req, res) => {
    const idx = parseInt(req.params.index, 10);
    fs.readFile(jsonPath, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Unable to read completed-projects.json' });
        let arr;
        try {
            arr = JSON.parse(data);
        } catch (e) {
            return res.status(500).json({ error: 'Invalid JSON format in completed-projects.json' });
        }
        if (idx < 0 || idx >= arr.length) return res.status(400).json({ error: 'Invalid index' });
        const project = arr[idx];
        arr.splice(idx, 1);
        fs.writeFile(jsonPath, JSON.stringify(arr, null, 2), err2 => {
            if (err2) return res.status(500).json({ error: 'Failed to delete project' });
            logAdminAction('DELETE_PROJECT', { ip: req.ip, index: idx, filename: project && project.src });
            // Delete image file if exists
            if (project && project.src) {
                const imgPath = path.join(__dirname, project.src.replace(/^\//, ''));
                fs.unlink(imgPath, err3 => {
                    // Ignore error if file doesn't exist
                    res.json({ success: true });
                });
            } else {
                res.json({ success: true });
            }
        });
    });
});

// --- Content Section CRUD (About, Contact, Products, Services) ---
const dataDir = path.join(__dirname, 'assets/data');

function getSectionPath(section) {
    const allowed = ['about', 'contact', 'products', 'services'];
    if (!allowed.includes(section)) return null;
    return path.join(dataDir, `${section}.json`);
}

// Get section data
app.get('/admin/section/:section', requireAdmin, (req, res) => {
    const filePath = getSectionPath(req.params.section);
    if (!filePath) return res.status(400).json({ error: 'Invalid section' });
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Unable to read section data' });
        try {
            res.json(JSON.parse(data));
        } catch (e) {
            res.status(500).json({ error: 'Invalid JSON format' });
        }
    });
});

// Update section data
app.post('/admin/section/:section', requireAdmin, express.json(), (req, res) => {
    const filePath = getSectionPath(req.params.section);
    if (!filePath) return res.status(400).json({ error: 'Invalid section' });
    fs.writeFile(filePath, JSON.stringify(req.body, null, 2), err => {
        if (err) return res.status(500).json({ error: 'Failed to save section data' });
        logAdminAction('UPDATE_SECTION', { ip: req.ip, section: req.params.section });
        res.json({ success: true });
    });
});

// Endpoint to get recent admin actions
app.get('/admin/log', requireAdmin, async (req, res) => {
    try {
        const logs = JSON.parse(await fs.promises.readFile(adminLogPath, 'utf8'));
        res.json(logs);
    } catch {
        res.json([]);
    }
});

// --- File/Image Management Endpoints ---
app.get('/admin/images', requireAdmin, (req, res) => {
    const folder = req.query.folder;
    const allowed = ['completed', 'products', 'services'];
    if (!allowed.includes(folder)) return res.status(400).json({ error: 'Invalid folder' });
    const dir = path.join(__dirname, 'assets/images', folder);
    fs.readdir(dir, (err, files) => {
        if (err) return res.status(500).json({ error: 'Unable to read images folder' });
        const images = files.filter(f => /\.(jpg|jpeg|png|gif|webp)$/i.test(f));
        res.json(images);
    });
});

app.delete('/admin/images', requireAdmin, express.json(), (req, res) => {
    const { folder, filename } = req.body;
    const allowed = ['completed', 'products', 'services'];
    if (!allowed.includes(folder)) return res.status(400).json({ error: 'Invalid folder' });
    if (!filename || /[\\/]/.test(filename)) return res.status(400).json({ error: 'Invalid filename' });
    const filePath = path.join(__dirname, 'assets/images', folder, filename);
    fs.unlink(filePath, err => {
        if (err) return res.status(500).json({ error: 'Failed to delete image' });
        logAdminAction('DELETE_IMAGE', { ip: req.ip, folder, filename });
        res.json({ success: true });
    });
});

// --- Public API for Site Content (no auth required) ---
app.get('/api/about', (req, res) => {
    fs.readFile(path.join(dataDir, 'about.json'), 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Unable to read about section' });
        try { res.json(JSON.parse(data)); } catch { res.status(500).json({ error: 'Invalid JSON' }); }
    });
});
app.get('/api/contact', (req, res) => {
    fs.readFile(path.join(dataDir, 'contact.json'), 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Unable to read contact section' });
        try { res.json(JSON.parse(data)); } catch { res.status(500).json({ error: 'Invalid JSON' }); }
    });
});
app.get('/api/products', (req, res) => {
    fs.readFile(path.join(dataDir, 'products.json'), 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Unable to read products section' });
        try { res.json(JSON.parse(data)); } catch { res.status(500).json({ error: 'Invalid JSON' }); }
    });
});
app.get('/api/services', (req, res) => {
    fs.readFile(path.join(dataDir, 'services.json'), 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Unable to read services section' });
        try { res.json(JSON.parse(data)); } catch { res.status(500).json({ error: 'Invalid JSON' }); }
    });
});

// Configure your SMTP transport here
const mailTransport = nodemailer.createTransport({
    service: process.env.SMTP_SERVICE || 'gmail',
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Contact form endpoint
app.post('/api/contact', express.json(), async (req, res) => {
    const { name, email, phone, message } = req.body;
    if (!name || !email || !message) return res.status(400).json({ error: 'Missing required fields' });
    try {
        await mailTransport.sendMail({
            from: 'yourcompanyemail@gmail.com',
            to: 'info@suntechpower.co.ke',
            subject: `New Contact Form Submission from ${name}`,
            text: `Name: ${name}\nEmail: ${email}\nPhone: ${phone||''}\nMessage: ${message}`
        });
        await updateAnalytics('contactSubmissions');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed to send email' });
    }
});

const analyticsPath = path.join(__dirname, 'assets/data/analytics.json');
async function updateAnalytics(field) {
    let stats = { pageViews: 0, contactSubmissions: 0, uploads: 0 };
    try { stats = JSON.parse(await fs.promises.readFile(analyticsPath, 'utf8')); } catch {}
    stats[field] = (stats[field] || 0) + 1;
    await fs.promises.writeFile(analyticsPath, JSON.stringify(stats, null, 2));
}
// Increment page views (for main site pages)
app.get('/api/analytics/pageview', async (req, res) => {
    await updateAnalytics('pageViews');
    res.json({ success: true });
});
// Endpoint to get analytics
app.get('/admin/analytics', requireAdmin, async (req, res) => {
    try {
        const stats = JSON.parse(await fs.promises.readFile(analyticsPath, 'utf8'));
        res.json(stats);
    } catch {
        res.json({ pageViews: 0, contactSubmissions: 0, uploads: 0 });
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
