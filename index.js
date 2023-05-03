
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const url = require('url');

const app = express();

var navLinks = [
    {name: "Home", link: "/"},
    {name: "About", link: "/about"},
    {name: "Contact", link: "/contact"},
    {name: "Members", link: "/members"},
    {name: "Administrator", link: "/admin"}
]

const Joi = require("joi");

const ObjectId = require('mongodb').ObjectId;

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

// Added line below to use EJS
app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, 
	saveUninitialized: false, 
	resave: true
}
));

// No need to modify
function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

// Implement this middleware to check if a user is logged in
function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.render('index');
    }
}

// Implement this middleware to check if a user is an admin
function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

// Implement this middleware to check if a user is an admin
function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

// Done
app.use("/", (req,res,next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
});

app.get('/', (req,res) => {
    if (!req.session.authenticated) {
    res.render('index');
    } else {
        res.render('loggedin-info', {username: req.session.username});
    }
});

// No need to modify
app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    res.render("about");
});

// Done
app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;

    res.render("contact", {missing: missingEmail});
});

// Done
app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.render("submitEmail", {email: email});
    }
});

// Done
app.get('/signUp', (req,res) => {
    res.render('signUp');
});

// Done
app.get('/login', (req,res) => {
    res.render('login');
});

// No need to modify
app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    var usertype = 'user';

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.render('signup_error', { errorMessage: validationResult.error.details[0].message });
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, email: email, user_type: usertype, password: hashedPassword});
	console.log("Inserted user");

    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = username;
    req.session.password = hashedPassword;
	req.session.user_type = usertype;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
});

// No need to modify
app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required(),
    });
	const validationResult = schema.validate({email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.render("login_error", {errorMessage: req.query.error});
	   return;
	}

	const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, username: 1, user_type: 1, _id: 1 }).toArray();

	console.log(result);
	if (result.length != 1) {
        res.render("login_error", {errorMessage: req.query.error});
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.email = email;
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedIn');
		return;
	}
	else {
		res.render("login_error", {errorMessage: req.query.error});
		return;
	}
});

app.use('loggedIn', sessionValidation);
app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else{
        res.redirect('/members');
    }
});

app.get('/logout', (req,res) => {
    req.session.destroy();
    res.clearCookie('connect.sid');
    res.render('index');
});

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }
    console.log(req.session);
    res.render('members', {username: req.session.username});
});

app.get('/admin', async (req,res) => {
    if (req.session.authenticated && req.session.user_type == 'admin') {
        const result = await userCollection.find().project({username: 1, user_type: 1, _id: 1}).toArray();
 
    res.render("admin", {users: result});
    } else {
        res.status(401).render("errorMessage", { error: "User not authorized" });
    }
});

app.get('/admin/promote/:id', sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.params.id;

    try {
        await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: "admin" } });
        res.redirect('/admin');
    } catch (err) {
        console.log(err);
        res.status(500).render("errorMessage", { error: "Error promoting user to admin" });
    }
});

app.get('/admin/demote/:id', sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.params.id;

    try {
        await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: "user" } });
        res.redirect('/admin');
    } catch (err) {
        console.log(err);
        res.status(500).render("errorMessage", { error: "Error demoting user to user" });
    }
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 