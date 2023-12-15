// Importing required modules
const nodemailer = require('nodemailer');  // For sending emails
const express = require('express');  // Web framework for Node.js
const cookieParser = require('cookie-parser');  // Parse HTTP request cookies
const { Client } = require('pg');  // PostgreSQL database client
const { MongoClient, ServerApiVersion } = require('mongodb');  // MongoDB client
const { Server } = require('ws');  // WebSocket server
const hbs = require('hbs');  // Handlebars.js for templating
const path = require('path');  // Path module for working with file and directory paths



// Importing the sha256 module for hashing
const sha256 = require('./sha256');

// Importing loginData and providing a path to the JSON data file
const loginData = require("./json/data.json");

// Storing currently logged-in users
const currentUsers = {};

// Storing users with pending OTP (One-Time Password) verification
const otpPending = {};

// Storing user details with pending actions
const userDetailsPending = {};

// MongoDB connection URI
const MongoDBURI = "mongodb+srv://user1:useradmin@cluster0.lokrddg.mongodb.net/?retryWrites=true&w=majority";

// Setting paths for Handlebars.js templates and partials
const templatePath = path.join(__dirname, './template/view');
const partialPath = path.join(__dirname, './template/partial');

// Registering Handlebars.js partials
hbs.registerPartials(partialPath);

// Creating a nodemailer transporter for sending emails
const MAILTRANSPORTER = nodemailer.createTransport({
    service: 'gmail',  // Using Gmail as the email service
    secureConnection: false,  // Allowing non-secure connections
    tls: {
        rejectUnauthorized: false,  // Disabling TLS unauthorized rejection
    },
    auth:{
        user: "thesocialnetworkproject8@gmail.com",  // Gmail account username
        pass: 'bral pmfc bvzp gqzs'  // Gmail account password (this should be kept secure)
    }
});

// Creating a MongoDB client with specific server API options
const MONGODBCLIENT = new MongoClient(MongoDBURI, {
    serverApi: {
        version: ServerApiVersion.v1,  // Using MongoDB Server API version 1
        strict: true,  // Enforcing strict mode for the server API
        deprecationErrors: true,  // Generating errors for deprecated features
    }
});

// Connecting to MongoDB
MONGODBCLIENT.connect()
    .then(res => console.log("MongoDB has been connected"))
    .catch(err => {
        throw err;  // Handling connection errors by throwing an exception
    });



// Creating an Express server instance
const server = express()
    .use(cookieParser())  // Adding middleware for parsing cookies
    .use([express.json(), express.static(__dirname), express.urlencoded()])  // Adding middleware for handling JSON, static files, and URL-encoded data

    .set('view engine', 'hbs')  // Setting Handlebars.js as the view engine
    .set('views', templatePath)  // Setting the views directory path

    // Handling GET requests for different routes
    .get("/", (req, res) => {
        res.header('redirected', true);
        res.redirect("/login/");
    })
    .get("/login", (req, res) => {
        login(req, res);
    })
    .get("/create", (req, res) => {
        res.render('create');  // Rendering the 'create' view using Handlebars.js
        // res.sendFile(__dirname+"/create/Create.html");
    })
    .get("/forgot", (req, res) => {
        res.sendFile(__dirname+"/forgot/Forgot.html");
    })
    .get("/terms", (req, res) => {
        res.sendFile(__dirname+"/terms/Terms.html");
    })
    .get("/chats", (req, res) => {
        if(req.cookies['session']) res.render('chats');  // Rendering the 'chats' view if the session cookie is present
        else res.redirect("/login/");
    })
    .get("/code", (req, res) => {
        res.sendFile(__dirname+"/code/Code.html");
    })
    .get("/details", (req, res) => {
        res.sendFile(__dirname + "/details/Details.html");
    })

    // Handling POST requests for different routes
    .post("/login", (req, res) => {
        setTimeout(() => console.log(currentUsers), 5000);  // Logging current users after a delay
        checkLogin(req, res);
    })
    .post("/create", (req, res) => {
        createAccount(req, res);
    })
    .post("/code", (req, res) => {
        verifyCode(req,res);
    })
    .post("/details", (req, res) => {
        addDetails(req, res);
    })
    .post("/forgot", (req, res) => {
        handleForgot(req, res);
    })
    .post("/user", (req, res) => {
        sendUserDetails(req, res);
    })
    .post("/logout", (req, res) => {
        res.clearCookie('session');  // Clearing the session cookie on logout
        res.json({code: "SUCCESS"});
    })
    .listen(4000,"10.7.2.217");  // Listening on port 4000

// Creating a WebSocket server using the Express server
const WSS = new Server({server});


// Handling WebSocket connections
WSS.on('connection', (ws) => {

    // Flag to check if WebSocket is assigned
    ws.isAssigned = false;

    // Handling incoming messages from the WebSocket
    ws.on('message', (data) => {

        // Parsing the incoming JSON message
        const message = JSON.parse(data);

        console.log(message);

        // Extracting the CODE from the message
        const CODE = message[0]

        // If WebSocket is not assigned and CODE is not 8, terminate the connection
        if(!ws.isAssigned && CODE !== 8) {
            ws.terminate();
            console.log("terminated");
            console.log("Code = "+CODE);
            console.log(ws.isAssigned);
        }

        // Handling different CODE cases
        if(CODE === 8)
        {
            // Assigning the WebSocket to the current user
            currentUsers[message[1]].ws = ws;
            ws.isAssigned = true;
            ws.sessionToken = message[1];
            ws.send(JSON.stringify([8]));  // Sending a response with CODE 8
        }
        else if(CODE === 1)
        {
            // Handling CODE 1 - Get Friends
            getFriends(ws);
        }
        else if(CODE === 4)
        {
            // Handling CODE 4 - Search User
            const searchString = message[1];
            console.log("Code = "+CODE);
            searchUser(searchString, ws);
        }
        else if(CODE === 5)
        {
            // Handling CODE 5 - Add Friend
            addFriend(message[1], ws);
        }
        else if(CODE === 2)
        {
            // Handling CODE 2 - Get Chats
            getChats(message[1], ws);
        }
        else if(CODE === 3)
        {
            // Handling CODE 3 - Forward Message
            forwardMessage(message[1], message[2], ws);
        }
    })
})

// Asynchronously forwards a message to a specified user's WebSocket
async function forwardMessage(username, message, ws)
{
    // Loop through currentUsers to find the WebSocket of the target user
    for(const keys in currentUsers)
    {
        // Check if the user is found and has an active WebSocket
        if(currentUsers[keys].username === username && currentUsers[keys].ws)
        {
            // Send the message to the target user's WebSocket
            currentUsers[keys].ws.send(JSON.stringify([3, message.from, message]));
            console.log("----"+currentUsers[keys].username)
        }
    }

    // Find the chat ID associated with the target user
    let chatid = null;
    currentUsers[ws.sessionToken].friends.forEach(value => {
        console.log(value);
        if(value.username === username) {
            chatid = value.chatid;
        }
    });

    // Update the MongoDB collection with the forwarded message
    const response = await MONGODBCLIENT.db('socialNetwork').collection('chats').updateOne({_id: chatid}, {$push: {messages: message}})
    console.log(response);
}



// Asynchronously retrieves chat messages for a specific user
async function getChats(username, ws)
{
    // Initialize variable to store the chat ID
    let chatid = null;

    // Loop through the user's friends to find the chat ID associated with the target user
    currentUsers[ws.sessionToken].friends.forEach(value => {
        console.log(value);
        if(value.username === username) {
            chatid = value.chatid;
        }
    });

    // Log currentUsers and the obtained chatid for debugging
    console.log(currentUsers);
    console.log(chatid);

    // Retrieve chat messages from MongoDB based on the chat ID
    const response = await MONGODBCLIENT.db('socialNetwork').collection('chats').findOne({_id: chatid});
    console.log(response);

    // Send the retrieved chat messages to the requesting WebSocket
    ws.send(JSON.stringify([2, username, response.messages]));
}

// Asynchronously adds a friend to the user's friend list
async function addFriend(username, ws)
{
    // Get the current user's details
    const user = currentUsers[ws.sessionToken];
    
    // Generate a unique chat ID for the new friend
    const chatid = userIdGenerator();
    console.log(user);
    
    // Flag to check if the friend already exists in the user's friends list
    let exists = false;

    // Check if the friend already exists, and if so, retrieve and send existing chat messages
    currentUsers[ws.sessionToken].friends.forEach(value => {
        if(value.username === username) {
            exists = true;
            getChats(username, ws);
        }
    });

    // If the friend already exists, exit the function
    if(exists) return;

    // Retrieve the friend's user ID based on the provided username
    const friendid = await getUserId(username);
    
    // Retrieve additional details about the friend
    const friendDetails = await getUserDetails(friendid);

    // Add the friend to the user's friends list
    currentUsers[ws.sessionToken].friends.push({
        id: friendid,
        username: username,
        name: friendDetails.name,
        about: friendDetails.about,
        imageCode: friendDetails.imageCode,
        chatid: chatid,
    });

    // Update MongoDB with the new friend information
    const result = await addFriendOnMongo(user.userid, friendid, chatid);

    // Notify the friend about the new connection
    for(const keys in currentUsers)
    {
        console.log(currentUsers[keys]);
        if(currentUsers[keys].userid === friendid && currentUsers[keys].ws)
        {
            currentUsers[keys].ws.send(JSON.stringify([5, {name: user.name, username: user.username, imageCode: user.imageCode, notification: true}]));
        }
    }

    // Notify the current user about the new connection
    ws.send(JSON.stringify([5, {name: friendDetails.name, username: username, imageCode: friendDetails.imageCode, notification: true}]))
}


// Asynchronously adds a friend connection to MongoDB
async function addFriendOnMongo(userid, friendid, chatid)
{
    // Define the document structure for the chat associated with the new friend
    const document = {
        _id: chatid,
        lasttime: new Date().getTime(),  // Timestamp of the last interaction with the chat
        messages: []  // Array to store chat messages
    };

    // Insert the chat document into the 'chats' collection
    const chatAdd = await MONGODBCLIENT.db('socialNetwork').collection('chats').insertOne(document);

    // Update the user's document in the 'users' collection by adding the new friend
    const userAdd = await MONGODBCLIENT.db('socialNetwork').collection('users').updateOne({_id: userid}, {$push: {friends: {id: friendid, chatid: chatid, notification: false}}});

    // Update the friend's document in the 'users' collection by adding the user as a friend
    const friendAdd = await MONGODBCLIENT.db('socialNetwork').collection('users').updateOne({_id: friendid}, {$push: {friends: {id: userid, chatid: chatid, notification: true}}});

    // Return true to indicate successful friend addition
    return true;
}


// Asynchronously retrieves and sends the list of friends for a user
async function getFriends(ws)
{
    // Retrieve the current user's details from the WebSocket session
    const user = currentUsers[ws.sessionToken];

    // Retrieve the user's document from MongoDB
    const results = await MONGODBCLIENT.db('socialNetwork').collection('users').findOne({_id: user.userid});

    // Arrays to store temporary and final friend details
    const temp = [];
    const sendList = [];

    // Iterate through each friend in the user's document
    for (const item of results.friends)
    {
        // Retrieve the username and additional details of the friend
        const username = await getUserName(item.id);
        const details = await getUserDetails(item.id);

        // Create temporary objects for sending to the client
        const temp1 = {
            id: item.id,
            username: username,
            name: details.name,
            about: details.about,
            imageCode: details.imageCode,
            chatid: item.chatid,
        }
        const temp2 = {
            username: username,
            name: details.name,
            about: details.about,
            imageCode: details.imageCode,
        }

        // Add the temporary objects to the arrays
        temp.push(temp1);
        sendList.push(temp2);
    }

    // Update the user's friends list with the temporary array
    currentUsers[ws.sessionToken].friends = temp;

    // Send the list of friends to the client
    ws.send(JSON.stringify([1, sendList]));
}


async function searchUser(searchString, ws)
{
    // const query = `select userid, username from user_credentials where username like '${searchString}%'`;
    const response = await MONGODBCLIENT.db('socialNetwork').collection('userCred').find({username: searchString});

    console.log(response)
    const result = await response.toArray()
    console.log(result)
    // const result = await POSTGRESCLIENT.query(query);
    // console.log(result);

    const temp = [];

    for (const value of result) {
        if(currentUsers[ws.sessionToken].username === value.username) continue;
        const data = await getUserDetails(value.userid);
        const temp1 = {
            username: value.username,
            name: data.name,
            imageCode: data.imageCode
        }
        console.log(temp1);
        temp.push(temp1);
    }
    console.log("temp");
    console.log(temp);
    ws.send(JSON.stringify([4, temp]));
}

async function sendUserDetails(req, res)
{
    const token = req.cookies['session'];
    if(currentUsers[token])
    {
        const temp = {
            username: currentUsers[token].username,
            name: currentUsers[token].name,
            about: currentUsers[token].about,
            imageCode: currentUsers[token].imageCode,
        };
        res.json(temp);
    }
    else {
        res.json({code: "FAIL"});
    }
}

async function handleForgot(req, res)
{
    const code = req.body.code;

    if(code === 1)
    {
        const email = req.body.email;
        const otpToken = tokenGenerator();
        res.cookie('token', otpToken);
        otpPending[otpToken] = {
            email: email
        }
        const status = await sendOTPMail(otpToken, email);
        res.json({code: "SUCCESS"})
    }
    else if(code === 2)
    {
        const veriCode = req.body.verificationcode;
        const token = req.cookies['token'];
        if(otpPending[token].code === parseInt(veriCode)) {
            res.clearCookie('token');
            const newToken = tokenGenerator();
            res.cookie('token', newToken)
            otpPending[newToken] = {
                email: otpPending[token].email
            }
            otpPending[token] = null;
            res.json({code: "SUCCESS"})
        }
        else res.json({code: "FAIL"});
    }
    else if(code === 3)
    {
        const token = req.cookies['token'];
        const password = req.body.password;
        const status = await updatePassword(otpPending[token].email, password)
        res.clearCookie('token');
        otpPending[token] = null;
        res.json({code: "SUCCESS"});
    }
}

async function updatePassword(email, password)
{
    // const query = `update user_credentials set password='${password}' where email='${email}'`
    const response = await MONGODBCLIENT.db('socialNetwork').collection('userCred').updateOne({email: email}, {$set: {password: password}});

    // const response = await POSTGRESCLIENT.query(query);
    return true
}

async function addDetails(req, res)
{
    const token = req.cookies['token'];

    if(!token) res.json({code: "FAIL"})
    else {
        const name = req.body.name;
        const about = req.body.about;
        const imageCode = Math.floor(Math.random()*20)+1;
        const userid = userIdGenerator();
        const lastActiveTime = new Date().getTime();
        userDetailsPending[token].name = name;
        userDetailsPending[token].about = about
        userDetailsPending[token].imageCode = imageCode;
        userDetailsPending[token].userid = userid;
        userDetailsPending[token].lastActiveTime = lastActiveTime;

        const userCredentialStatus = await addUserCredentials(token);
        const userDetailsStatus = await addUserDetails(token);
        const sessionToken = tokenGenerator();
        const sessionAdded = await addSessionToken(sessionToken, userid);
        const mongoAdded = await addUserOnMongoDB(userid);

        res.clearCookie('token');
        res.cookie('session', sessionToken);
        res.json({code: "SUCCESS"});

    }
}

async function addUserOnMongoDB(userid)
{
    const document = {
        _id: userid,
        friends: [],
        groups: []
    }
    const results = await MONGODBCLIENT.db('socialNetwork').collection("users").insertOne(document);
    console.log(results);
    return true
}

async function addUserCredentials(token)
{
    const document = {
        userid: userDetailsPending[token].userid,
        username: userDetailsPending[token].username,
        password: userDetailsPending[token].password,
        email: userDetailsPending[token].email
    }
    const response = await MONGODBCLIENT.db('socialNetwork').collection("userCred").insertOne(document);
    return true
}

async function addUserDetails(token)
{
    const document = {
        userid: userDetailsPending[token].userid,
        name: userDetailsPending[token].name,
        about: userDetailsPending[token].about,
        imageCode: userDetailsPending[token].imageCode,
        lastActiveTime: userDetailsPending[token].lastActiveTime
    }


    // const query = `insert into user_details values('${userDetailsPending[token].userid}', '${userDetailsPending[token].name}', '${userDetailsPending[token].about}', '${userDetailsPending[token].imageCode}', '${userDetailsPending[token].lastActiveTime}')`

    const response = await MONGODBCLIENT.db('socialNetwork').collection("userDetails").insertOne(document);
    return true
}

async function verifyCode(req, res)
{
    const code = req.body.code;
    const token = req.cookies['token'];

    if(!otpPending[token]) res.json({code: "FAIL"});
    else
    {
        if(otpPending[token].code !== parseInt(code)){
            res.json({code: "FAIL"});
        }
        else
        {
            const newToken = tokenGenerator();
            userDetailsPending[newToken] = {
                username: otpPending[token].username,
                password: otpPending[token].password,
                email: otpPending[token].email,
            }
            otpPending[token] = null;

            res.cookie('token', newToken);
            res.json({code: "SUCCESS"})

        }
    }


}

async function createAccount(req, res)
{
    const password = req.body.password;
    const username = req.body.username;
    const email = req.body.email;

    const exists = await checkUsernameAndEmail(username, email);

    if(exists){
        res.json({code: "EXISTS"});
    }
    else
    {
        const otpToken = tokenGenerator();

        otpPending[otpToken] = {
            username: username,
            password: password,
            email: email,
        }

        const message = await sendOTPMail(otpToken, email);

        res.cookie('token', otpToken);

        res.json({code: "SUCCESS"})
    }
}

// Asynchronously sends an email with a verification code
async function sendOTPMail(optToken, email)
{
    // Generate a random verification code
    const code = Math.floor(Math.random() * 900000) + 100000;

    // Create an email object with the verification code
    const mail = {
        from: "thesocialnetworkproject8@gmail.com",
        to: email,
        subject: "The Social Network - Verification Code",
        text: `The verification code for your The Social Network account is - ${code}`
    }

    // Send the email using the nodemailer transporter
    MAILTRANSPORTER.sendMail(mail, (error, info) =>
    {
        // Return "SUCCESS" to indicate successful email sending
        return "SUCCESS";
    });

    // Update the verification code in the otpPending object
    otpPending[optToken].code = code;
}

async function checkUsernameAndEmail(username, email)
{
    // const query = `select * from user_credentials where username='${username}' or email='${email}';`

    const response = await MONGODBCLIENT.db('socialNetwork').collection('userCred').findOne({username: username});
    const response1 = await MONGODBCLIENT.db('socialNetwork').collection('userCred').findOne({email: email});
    // const response = await POSTGRESCLIENT.query(query);
    console.log(response)
    return !(response === null && response1 === null);

}


async function checkLogin(req, res)
{
    const password = req.body.password;
    const username = req.body.username;
    let userid = null
    console.log(req.body)

    // const query = `select userid from user_credentials where username='${username}' and password='${password}'`;
    const response = await MONGODBCLIENT.db('socialNetwork').collection('userCred').findOne({username: username, password: password});
    console.log(response)
    if (response == null){
        res.json({code: "FAIL"});
    }
    else {
        userid = response.userid;
        const sessionToken = tokenGenerator();
        addSessionToken(sessionToken, userid).then(data => {
            res.cookie('session', sessionToken);
            res.json({code: "SUCCESS"});
        })
    }


    // POSTGRESCLIENT.query(query, (err, response) => {
    //     if ( err ) {
    //         throw err;
    //     }
    //     else {
    //
    //         if(response.rows.length === 0) res.json({code: "FAIL"});
    //         else {
    //             userid = response.rows[0].userid;
    //             const sessionToken = tokenGenerator();
    //             addSessionToken(sessionToken, userid).then(data => {
    //                 res.cookie('session', sessionToken);
    //                 res.json({code: "SUCCESS"});
    //             })
    //         }
    //     }
    // })


}

async function addSessionToken(sessionToken, userid)
{
    const document = {
        sessionToken: sessionToken,
        userid: userid
    }

    const response = await MONGODBCLIENT.db('socialNetwork').collection("sessionTokens").insertOne(document);
    return true

    // const query = `insert into session_tokens values('${sessionToken}', '${userid}')`;

    // POSTGRESCLIENT.query(query, (err, response) => {
    //     if ( err ) throw err;
    //     else {
    //         return "SUCCESS"
    //     }
    // })
}

async function login(req, res)
{
    const sessionToken = req.cookies['session'];

    if ( sessionToken )
    {
        sessionGetUserId(sessionToken)
            .then(userid => {
                if(userid)
                {
                    makeLogin(userid, sessionToken)
                        .then(data => {
                            res.header('redirected', true);
                            res.redirect("/chats/");
                        });
                }
                else {
                    res.clearCookie('session');
                    res.render('login', loginData);
                }
            });
    }
    else
    {
        res.render('login', loginData);
    }
}

async function makeLogin(userid, sessionToken)
{
    const username = await getUserName(userid);
    const details = await getUserDetails(userid);

    if (!details || !username) {
        throw new Error("Problem with user data");
    }

    currentUsers[sessionToken] = {
        userid: userid,
        username: username,
        name: details.name,
        about: details.about,
        imageCode: details.imageCode,
    }

    return "SUCCESS"
}

async function getUserName(userid)
{
    // const query = `select username from user_credentials where userid='${userid}'`;

    const response = await MONGODBCLIENT.db('socialNetwork').collection('userCred').findOne({userid: userid});
    return response.username
    // const response = await POSTGRESCLIENT.query(query);
    // if(response.rows.length === 0) return false;
    // return response.rows[0].username;
}

async function getUserDetails(userid)
{
    // const query = `// select name,about,image_code from user_details where userid='${userid}'`;

    const response = await MONGODBCLIENT.db('socialNetwork').collection('userDetails').findOne({userid: userid});
    console.log(response)
    if (response == null) return false;
    return response;
    // const response = await POSTGRESCLIENT.query(query)
    // if(response.rows.length === 0) return false;
    // return response.rows[0];
}

async function getUserId(username)
{
    // const query = `select userid from user_credentials where username='${username}'`;

    const response = await MONGODBCLIENT.db('socialNetwork').collection('userCred').findOne({username: username});
    console.log(response)
    return response.userid
    // const response = await POSTGRESCLIENT.query(query);
    // console.log(response);
    // return response.rows[0].userid;
}

async function sessionGetUserId(session)
{
    // const query = `select userid from session_tokens where session_token='${session}'`;
    const response = await MONGODBCLIENT.db('socialNetwork').collection('sessionTokens').findOne({sessionToken: session});

    if (response == null) return false;
    return response.userid
    // const response = await POSTGRESCLIENT.query(query)
    // if(response.rows.length === 0) return false
    // return response.rows[0].userid
}

function tokenGenerator()
{
    let string = ""
    for ( let i = 0 ; i < 20 ; i++ )
        string = string + String.fromCharCode(Math.floor(Math.random() * 26) + 65);
    return sha256(string);
}

function userIdGenerator()
{
    let string = ""
    for ( let i = 0 ; i < 20 ; i++ )
        string = string + String.fromCharCode(Math.floor(Math.random() * 26) + 65);
    return string;
}