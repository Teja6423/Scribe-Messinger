import express from 'express';
import bodyParser from 'body-parser';
import pkg from 'pg'; // Import pg module as default
const { Pool } = pkg; // Extract Pool from pg
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

const db = new Pool({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
    ssl: false
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
    const activeConversation = await db.query(`
        SELECT m.sender_id as user, m.receiver_id, u.username as friend_name, m.content as message, m.timestamp as time 
        FROM messages m
        INNER JOIN users u ON u.id = m.receiver_id
        WHERE m.sender_id = $1 OR m.receiver_id = $1
        ORDER BY time DESC;
        `, [id]
    );
    const friends_list = await db.query(`
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

    return { friends: friends, data: data };
}


// Render home page
app.all('/home', async (req, res) => {
    if (req.isAuthenticated()) {
        const friendId = req.query.friend_id || req.body.friend_id;
        const message = req.body.message; 
        const type = req.query.type || 'success'; 

        let x = await fetchData(req.user.id);
        const data = [];
        const friend_0 = x.friends[0]?.friend_id;
        let friend = friendId || friend_0;

        if (message) {
            try {
                await db.query(`

                    INSERT INTO messages (sender_id, receiver_id, content,timestamp)
                    VALUES ($1, $2, $3,CURRENT_TIMESTAMP AT TIME ZONE 'Asia/Kolkata')
                `, [req.user.id, friend, message]);
            } catch (err) {
                console.log(err);
                res.redirect('/');
                return;
            }
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

        // Send JSON response
        if (req.headers['accept'] === 'application/json') {
            res.json({ messages: data });
        } else {
            res.render('home', {
                friends: x.friends,
                userdata: req.user,
                messages: data,
                friend_name: x.friends.find(f => f.friend_id == friend)?.friend_name || "Friend's Username",
                friend_id: friend,
                message, // Pass the message for popup
                type // Pass the type for popup
            });
        }
    } else {
        res.redirect('/');
    }
});



  
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const emailResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (emailResult.rows.length > 0) {
            return res.redirect('/?message=Email already exists, try logging in.&type=error');
        }

        const usernameResult = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        if (usernameResult.rows.length > 0) {
            return res.redirect('/?message=Username already exists.&type=error');
        }

        bcrypt.hash(password, saltRounds, async (err, hash) => {
            if (err) {
                console.log('Error hashing password', err);
                return res.redirect('/?message=Error hashing password&type=error');
            }
            await db.query('INSERT INTO users (username, email, password) VALUES ($1, $2, $3)', [username, email, hash]);
            res.redirect('/?message=User registered successfully!&type=success');
        });
    } catch (err) {
        console.log(err);
        res.redirect('/?message=Server error&type=error');
    }
});

app.get('/check-username', async (req, res) => {
    const username = req.query.username;
    try {
        const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
        res.json({ available: result.rows.length === 0 });
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: 'Server error' });
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
            console.log(err);
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
        const userResult = await db.query('SELECT id FROM users WHERE username = $1', [username]);

        if (userResult.rows.length === 0) {
            return res.redirect('/home/?message=User not found.&type=error');
        }

        const userId = userResult.rows[0].id;

        if (userId == Number(req.user.id)) {
            return res.redirect('/home/?message=Enter a valid user ID, not yours.&type=error');
        }

        if (friendIDs.includes(Number(userId))) {
            return res.redirect('/home?message=You are already friends with this user.&type=error');
        }

        await db.query('INSERT INTO friends (user_id, friends_id, active_conversation) VALUES ($1, $2, true),($2, $1, true)', [req.user.id, userId]);
        res.redirect('/home/?message=Friend added successfully.&type=success');
        
    } catch (error) {
        console.error(error);
        res.redirect('/home/?message=Server error.&type=error');
    }
});

// Passport configuration
passport.use(new Strategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (user) {
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                return done(null, user);
            }
        }
        return done(null, false, { message: 'Incorrect username or password.' });
    } catch (err) {
        console.log(err);
        return done(err);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
        const user = result.rows[0];
        done(null, user);
    } catch (err) {
        console.log(err);
        done(err);
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
