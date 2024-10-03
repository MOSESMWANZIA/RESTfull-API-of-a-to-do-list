const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

app.use(express.json());

// In-memory storage for items and users
let items = [];
let users = [];

// Secret key for JWT
const SECRET_KEY = '1111';

// JWT Middleware to protect routes
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract the token

    if (!token) return res.status(401).json({ error: 'Access denied, no token provided' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user; // Store user information in the request
        next();
    });
}

// User registration (POST /register)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Check if username and password are provided
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    // Check if username already exists
    const existingUser = users.find(u => u.username === username);
    if (existingUser) return res.status(400).json({ error: 'Username already exists' });

    try {
        // Hash the password before saving
        const saltRounds = 10; // Define the salt rounds
        const hashedPassword = await bcrypt.hash(password, saltRounds); // Pass password and saltRounds

        const user = { id: users.length + 1, username, password: hashedPassword };
        users.push(user);

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error registering user' });
    }
});

// User login (POST /login)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user) return res.status(400).json({ error: 'Invalid username or password' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid username or password' });

    // Generate a token
    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// Get items with search, sorting, and filtering (GET /items)
app.get('/items', (req, res) => {
    let filteredItems = items;

    // Search by name (case insensitive)
    if (req.query.name) {
        const name = req.query.name.toLowerCase();
        filteredItems = filteredItems.filter(item => item.name.toLowerCase().includes(name));
    }

    // Filter by completed status
    if (req.query.completed) {
        const isCompleted = req.query.completed === 'true';
        filteredItems = filteredItems.filter(item => item.completed === isCompleted);
    }

    // Sort items (default is ascending order)
    if (req.query.sortBy) {
        const sortBy = req.query.sortBy;
        const sortOrder = req.query.order === 'desc' ? -1 : 1;
        filteredItems.sort((a, b) => {
            if (a[sortBy] < b[sortBy]) return -1 * sortOrder;
            if (a[sortBy] > b[sortBy]) return 1 * sortOrder;
            return 0;
        });
    }

    res.json(filteredItems);
});

// Add a new item (POST /items) - Protected route
app.post('/items', authenticateToken, (req, res) => {
    const newItem = {
        id: items.length + 1,
        name: req.body.name,
        completed: false,
    };
    items.push(newItem);
    res.status(201).json(newItem);
});

// Update an existing item (PUT /items/:id) - Protected route
app.put('/items/:id', authenticateToken, (req, res) => {
    const id = parseInt(req.params.id);
    const item = items.find(item => item.id === id);

    if (!item) return res.status(404).json({ error: 'Item not found' });

    item.name = req.body.name || item.name;
    item.completed = req.body.completed ?? item.completed;
    res.json(item);
});

// Delete an item (DELETE /items/:id) - Protected route
app.delete('/items/:id', authenticateToken, (req, res) => {
    const id = parseInt(req.params.id);
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex === -1) return res.status(404).json({ error: 'Item not found' });

    items.splice(itemIndex, 1);
    res.status(204).send();
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
