const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cors = require('cors');

const app = express();
// Render asigna dinámicamente el puerto a través de process.env.PORT
const PORT = process.env.PORT || 3000;
const ACCOUNTS_FILE = path.join(__dirname, 'accounts.json');

app.use(express.json());
app.use(cors({
    origin: true,
    credentials: true
}));

app.use(session({
    secret: 'monkeymod_super_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
}));

// Inicializar accounts.json si no existe
if (!fs.existsSync(ACCOUNTS_FILE)) {
    fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify([]));
}

const getAccounts = () => JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
const saveAccounts = (data) => fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(data, null, 2));

// API REGISTRO
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Faltan campos' });

    const accounts = getAccounts();
    if (accounts.find(acc => acc.username.toLowerCase() === username.toLowerCase())) {
        return res.status(400).json({ error: 'El nombre de usuario ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: Date.now().toString(),
        username,
        password: hashedPassword,
        createdAt: new Date().toISOString()
    };

    accounts.push(newUser);
    saveAccounts(accounts);

    req.session.user = { id: newUser.id, username: newUser.username };
    res.json({ success: true, user: req.session.user });
});

// API LOGIN
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const accounts = getAccounts();
    const user = accounts.find(acc => acc.username.toLowerCase() === username.toLowerCase());

    if (!user) return res.status(400).json({ error: 'Usuario no encontrado' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Contraseña incorrecta' });

    req.session.user = { id: user.id, username: user.username };
    res.json({ success: true, user: req.session.user });
});

// API VERIFICAR SESIÓN
app.get('/api/me', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

// API LOGOUT
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`Servidor MonkeyMod activo en el puerto ${PORT}`));
