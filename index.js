const express = require('express');       // load express module
const nedb = require("nedb-promises");    // load nedb module
const bcrypt = require("bcrypt");

const app = express();                    // init app
const db = nedb.create('users.jsonl');    // init db

app.use(express.static('public'));        // enable static routing to "./public" folder

//TODO:
// automatically decode all requests from JSON and encode all responses into JSON
app.use(express.json());

//TODO:
// create route to get all user records (GET /users)
//   use db.find to get the records, then send them
//   use .catch(error=>res.send({error})) to catch and send errors
app.get('/users', (req, res) => {
    db.find({})
    .then(docs => res.send(docs))
    .catch(error => res.send({error}));
});

//TODO:
// create route to get user record (GET /users/:username)
//   use db.findOne to get user record
//     if record is found, send it
//     otherwise, send {error:'Username not found.'}
//   use .catch(error=>res.send({error})) to catch and send other errors

// modified to make it secure
app.post('/authorization', (req, res) => {
    db.findOne({username: req.body.username})
    .then(doc => {
        console.log(doc);
        if(doc) {
            //updating the doc with token number 
            if(bcrypt.compareSync(req.body.password, doc.password)) {
                doc.token = "" + Math.random();
                db.updateOne(
                    {username: req.body.username},   
                    {$set: {token: doc.token}});
                delete doc.password;
                res.send(doc);
            }
            else {
                res.send({error: "Login Failed!"});
            }
        }
        else {
            res.send({error: 'Username not found.'});
        }
    })
    .catch(error => res.send({error}));
});

//TODO:
// create route to register user (POST /users)
//   ensure all fields (username, password, email, name) are specified; if not, send {error:'Missing fields.'}
//   use findOne to check if username already exists in db
//     if username exists, send {error:'Username already exists.'}
//     otherwise,
//       use insertOne to add document to database
//       if all goes well, send returned document
//   use .catch(error=>res.send({error})) to catch and send other errors

//modified post to add hashed password and salt to the doc
app.post('/users', (req, res) => {
    const user = req.body;

    if(!user.hasOwnProperty('username') || 
        !user.hasOwnProperty('password') ||
        !user.hasOwnProperty('email') || 
        !user.hasOwnProperty('name')) {
        res.send({error : 'Missing fields.'});
    }
    else {
        db.findOne({username : user.username})
        .then(doc => {
            if(doc) {
                res.send({error : 'Username already exists.'});
            }
            else {
                user.password = bcrypt.hashSync(user.password, bcrypt.genSaltSync());
                user.token = "" + Math.random();

                db.insertOne(user)
                .then(doc => {
                    delete doc.password;
                    res.send(doc)})
                .catch(error => res.send({error}));
            }
        })
        .catch(error => res.send({error}));
    }
});

//TODO:
// create route to update user doc (PATCH /users/:username)
//   use updateOne to update document in database
//     updateOne resolves to 0 if no records were updated, or 1 if record was updated
//     if 0 records were updated, send {error:'Something went wrong.'}
//     otherwise, send {ok:true}
//   use .catch(error=>res.send({error})) to catch and send other errors
app.patch('/users/:username/:token', (req, res) => {
   db.updateOne(
    {username: req.params.username,
    token: req.params.token},
    {$set: req.body})
    .then(result => {
        if(result == 0) {
            res.send({error: 'Something went wrong.'});
        }
        else {
            res.send({ok : true});
        }
    })
    .catch(error => res.send({error})); 
});

//TODO:
// create route to delete user doc (DELETE /users/:username)
//   use deleteOne to update document in database
//     deleteOne resolves to 0 if no records were deleted, or 1 if record was deleted
//     if 0 records were deleted, send {error:'Something went wrong.'}
//     otherwise, send {ok:true}
//   use .catch(error=>res.send({error})) to catch and send other errors
app.delete('/users/:username/:token', (req, res) => {
    db.deleteOne(
        {username : {$exists : true},
        token: req.params.token})
    .then(result => {
        if(result == 0) {
            res.send({error : 'Something went wrong.'});
        }
        else {
            res.send({ok : true});
        }
    })
    .catch(error => res.send({error}));
});

// default route
app.all('*',(req,res) => {
    res.status(404).send('Invalid URL.')});

// start server
app.listen(3000,() => {
    console.log("Server started on http://localhost:3000")});
