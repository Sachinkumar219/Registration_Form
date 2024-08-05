const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const path = require('path');
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/userDB', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log('MongoDB connection error:', err));

// Create a schema for users
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

// Create a model for users
const User = mongoose.model('User', userSchema);

// Serve the login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Serve the registration page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

// Handle registration
app.post('/register', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    const confirmPassword = req.body['confirm-password'];

    // Password validation regex
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    // Check if passwords match
    if (password !== confirmPassword) {
        return res.redirect('/register?error=Passwords do not match.');
    }

    // Check if password meets requirements
    if (!passwordRegex.test(password)) {
        return res.redirect('/register?error=Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 8 characters long.');
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.redirect('/register?error=User already exists. Please log in.');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            email: email,
            password: hashedPassword
        });

        await newUser.save();
        res.redirect('/?success=Successfully registered. Please log in.');
    } catch (err) {
        console.log('Error during registration:', err);
        res.send(err);
    }
});

// Handle login
app.post('/login', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    try {
        const foundUser = await User.findOne({ email: email });

        if (foundUser) {
            const isMatch = await bcrypt.compare(password, foundUser.password);

            if (isMatch) {
                res.redirect(`/welcome?email=${encodeURIComponent(email)}`);
            } else {
                res.redirect('/?error=Incorrect password.');
            }
        } else {
            res.redirect('/?error=No user found with that email.');
        }
    } catch (err) {
        console.log('Error during login:', err);
        res.send(err);
    }
});

// Serve the welcome page
app.get('/welcome', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'welcome.html'));
});

// Handle logout
app.get('/logout', (req, res) => {
    res.redirect('/?success=Successfully logged out.');
});

// Start the server on port 3000
app.listen(3000, () => {
    console.log('Server started on http://localhost:3000');
});
