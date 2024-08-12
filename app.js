import express from 'express';
import bodyParser from 'body-parser';
import pkg from 'pg'; // Import the default export from pg
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import session from 'express-session';
import passport from 'passport';
import { Strategy } from 'passport-local';
import multer from 'multer';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

const upload = multer(); // Initialize multer without storage configuration
app.use(upload.none());

// Use Pool from pg
const { Pool } = pkg;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Remove or modify the SSL configuration
    // ssl: {
    //     rejectUnauthorized: false // Remove this if SSL is not supported
    // }
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(express.json()); // for parsing application/json

app.set('view engine', 'ejs');

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

// Render login/register page with messages
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/home');
    } else {
        const message = req.query.message;
        const type = req.query.type;
        res.render('auth', { message, type });
    }
});

// Fetch conversations and messages
async function fetchData(id) {
    const data = [];
    const friends = [];
    try {
        const activeConversation = await pool.query(`
            SELECT m.sender_id AS user, m.receiver_id, u.username AS friend_name, m.content AS message, m.timestamp AS time
            FROM messages m
            INNER JOIN users u ON u.id = m.receiver_id
            WHERE m.sender_id = $1 OR m.receiver_id = $1
            ORDER BY time DESC;
        `, [id]);

        const friends_list = await pool.query(`
            SELECT f.user_id, f.friends_id, u.username
            FROM friends f
            INNER JOIN users u ON u.id = f.friends_id
            WHERE f.user_id = $1
        `, [id]);

        activeConversation.rows.forEach(user => {
            data.push({
                sender_id: user.user,
                friend_name: user.friend_name,
                receiver_id: user.receiver_id,
                message: user.message,
                time: user.time
            });
        });

        friends_list.rows.forEach(name => {
            friends.push({ friend_name: name.username, friend_id: name.friends_id });
        });

    } catch (err) {
        console.error('Error fetching data:', err);
    }
    return { friends, data };
}

// Render home page
app.all('/home', async (req, res) => {
    if (req.isAuthenticated()) {
        const friendId = req.query.friend_id || req.body.friend_id;
        const message = req.body.message;
        const type = req.query.type || 'success';

        try {
            let x = await fetchData(req.user.id);
            const data = [];
            const friend_0 = x.friends[0]?.friend_id;
            let friend = friendId || friend_0;

            if (message) {
                await pool.query(`
                    INSERT INTO messages (sender_id, receiver_id, content)
                    VALUES ($1, $2, $3)
                `, [req.user.id, friend, message]);
            }

            x = await fetchData(req.user.id);

            x.data.forEach(msg => {
                if (
                    (msg.sender_id == req.user.id && msg.receiver_id == friend) ||
                    (msg.sender_id == friend && msg.receiver_id == req.user.id)
                ) {
                    const dateObj = new Date(msg.time);
                    const options = {
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                        hour12: false
                    };
                    const formattedDate = dateObj.toLocaleDateString('en-US', options);
                    const formattedTime = dateObj.toLocaleTimeString('en-US', options);
                    const formattedDateTime = `${formattedTime}`;

                    data.push({
                        receiver_id: msg.receiver_id,
                        message: msg.message,
                        time: formattedDateTime
                    });
                }
            });

            res.render('home', {
                friends: x.friends,
                userdata: req.user,
                messages: data,
                friend_name: x.friends.find(f => f.friend_id == friend)?.friend_name || "Friend's Username",
                friend_id: friend,
                message, // Pass the message for popup
                type // Pass the type for popup
            });

        } catch (err) {
            console.error('Error rendering home page:', err);
            res.status(500).send('Internal Server Error');
        }
    } else {
        res.redirect('/');
    }
});

// Register user
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const emailResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (emailResult.rows.length > 0) {
            return res.redirect('/?message=Email already exists, try logging in.&type=error');
        }

        const usernameResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (usernameResult.rows.length > 0) {
            return res.redirect('/?message=Username already exists.&type=error');
        }

        bcrypt.hash(password, saltRounds, async (err, hash) => {
            if (err) {
                console.error('Error hashing password', err);
                return res.redirect('/?message=Error hashing password&type=error');
            }
            await pool.query('INSERT INTO users (username, email, password) VALUES ($1, $2, $3)', [username, email, hash]);
            res.redirect('/?message=User registered successfully!&type=success');
        });
    } catch (err) {
        console.error('Error registering user:', err);
        res.redirect('/?message=Server error&type=error');
    }
});

// Login user
app.post('/login', passport.authenticate('local', {
    successRedirect: '/home?message=Logged in Successfully&type=success',
    failureRedirect: '/?message=Wrong email or password&type=error',
}));

// Logout user
app.post('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Error logging out:', err);
            return res.redirect('/?message=Error logging out&type=error');
        }
        res.redirect('/?message=Logged out successfully&type=success');
    });
});

// Add friend
app.post('/add-friend', async (req, res) => {
    const { username } = req.body;

    try {
        let x = await fetchData(req.user.id);
        const friendIDs = x.friends.map(friend => friend.friend_id);
        const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [username]);

        if (userResult.rows.length === 0) {
            return res.redirect('/home?message=User not found.&type=error');
        }

        const userId = userResult.rows[0].id;

        if (userId == Number(req.user.id)) {
            return res.redirect('/home?message=Enter a valid user ID, not yours.&type=error');
        }

        if (friendIDs.includes(Number(userId))) {
            return res.redirect('/home?message=You are already friends with this user.&type=error');
        }

        await pool.query('INSERT INTO friends (user_id, friends_id, active_conversation) VALUES ($1, $2, true)', [req.user.id, userId]);
        res.redirect('/home?message=Friend added successfully.');
        
    } catch (error) {
        console.error('Error adding friend:', error);
        res.redirect('/home?message=Server error.');
    }
});

// Passport configuration
passport.use(new Strategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (user) {
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                return done(null, user);
            }
        }
        return done(null, false, { message: 'Incorrect username or password.' });
    } catch (err) {
        console.error('Error in passport strategy:', err);
        return done(err);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        const user = result.rows[0];
        done(null, user);
    } catch (err) {
        console.error('Error deserializing user:', err);
        done(err);
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
