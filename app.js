const express = require('express')
const { Client } = require('pg')
const jwt = require('jsonwebtoken')
const auth = require('./Auth/auth')
const {hash} = require('./userFuncs/funcs')
const validator = require('validator')

// A connection is made with ElephantSQL database
const ElephSQLConStr = process.env.ESQL_URL
const client = new Client(ElephSQLConStr)

client.connect()

//Creating the table with the name 'users' to store users information

const newTable = "CREATE TABLE IF NOT EXISTS users( id SERIAL PRIMARY KEY ,name varchar(25) NOT NULL UNIQUE,email varchar(50) NOT NULL UNIQUE, password varchar(100) NOT NULL,phone varchar(20), age INT , tokens varchar(180))"

client.query(newTable, (err, res) => {
    if(err) {
        return console.log(err.message)
    }
    console.log('Done')
})
const app = express()

app.use(express.json())

const port = process.env.PORT

app.post('/signup', async (req, res) => {
    // This endpoint creates a user profile provided the email is unique and valid, password is strong enough and
    // phone number is valid 
    try{
        // Email is validated
        if (validator.isEmail(req.body.email)) {
            console.log('valid mail')
            // Phone number is validated
            if(validator.isMobilePhone(req.body.phone)){
                console.log('valid phone')
                //Password strenfth is confirmed
                if(req.body.password.length > 6 && !req.body.password.toLowerCase().includes('password')){
                    const token = jwt.sign({pass:req.body.email}, process.env.secret)

                    // The password is hashed for integrity and the user is added to the database
                    const gen_hash = hash(req.body.password)
                    await client.query(`INSERT INTO users (name, email, password, phone, age, tokens) VALUES($1, $2, $3, $4, $5, $6)`,[req.body.name,req.body.email,gen_hash,req.body.phone,req.body.age,[token]])
                    const user = await client.query(`SELECT name,email,age FROM users WHERE name = $1`,[req.body.name])
                    res.status(201).send({user:user.rows[0],token})
                    console.log('New user added') 
                }
                else{
                    throw new Error('Password must have more than 6 characters and should not include `password`')
                }
            }
            else{
                throw new Error('Please provide a valid phone number')
            }
        }
        else {
            throw new Error('Please provide a valid email address')
        }
   
    }
    catch(e){
        console.log(e.message)
        res.status(400).send(e.message)
    }
})

app.post('/users/login', async (req, res) => {
    // The user can log in with an existing email and registered password with the help of a jsonwebtoken
    // Error is sent if email does not exist or if an incorrect password is provided
    try{
        const user = await client.query(`SELECT * FROM users where email = $1`,[req.body.email])
        if (user.rowCount === 0 || !req.body.password || !req.body.email) {
            return res.status(400).send('Login unsuccessful')
        }
        
        // provided password is hashed
        const gen_hash = hash(req.body.password)

        // The hashed password is compared to one in the database
        if (gen_hash !== user.rows[0].password) {
            return res.send('Login unsuccessful')
        }

        // Jsonwebtoken is created to log the user in
        const token = jwt.sign({pass:req.body.email}, process.env.secret)
        await client.query(`UPDATE users SET  tokens = $1 WHERE email=$2`,[[token],req.body.email])
        const logged_in = await client.query(`SELECT name, email, age FROM users where email = $1`,[req.body.email])

        res.status(202).send({user:logged_in.rows[0],token})
        console.log('User logged in')
    }
    catch(e) {
        console.log(e)
        res.status(401).send(e)
    }
})

app.get('/users', auth, async (req, res) => {
    // This endpoint allows the user to view their profile only if they are logged in. This is made possible with use of jsonwebtoken
    try{
        res.status(202).send(req.user)
    }
    catch(e) {
        console.log(e)
        res.status(401).send(e)
    }
})

app.patch('/users/me', auth, async(req, res) => {
    // user profile can be updated. A user has to be logged in for this. The password is hashed and other validations are checked
    try{
        const user = await client.query('SELECT * FROM users WHERE email = $1',[req.user.email])

        for (obj in req.body){
            if (obj == 'password'){
                //If password is to be updated, it gets hashed before getting stored in the database
                const hashed = hash(req.body[obj])
                await client.query(`UPDATE users SET ${obj} = $1 WHERE tokens = $2`,[hashed,[auth_token]])
            }
            else{
                await client.query(`UPDATE users SET ${obj} = $1 WHERE tokens = $2`,[req.body[obj],[auth_token]])
            }
        }
        const update = await client.query('SELECT name,email,age FROM users WHERE tokens = $1',[[auth_token]])
        res.status(202).send(update.rows[0])
    }
    catch(e) {
        console.log(e)
        res.status(401).send(e)
    }
})

app.get('/users/logout', auth, async(req, res) => {
    // User gets logged out by remmoving the jsonwebtoken
    try{
        await client.query(`UPDATE users SET name = $1, email = $2, password = $3, phone = $4, age = $5, tokens =$7 WHERE email =$6`,[req.user.name,req.user.email,req.user.password,req.user.phone,req.user.age,req.user.email,''])
        console.log('User logged out')
        res.status(200).send('Logged out')
    }
    catch(e) {
        res.status(401).send(e)
        console.log(e)
    }
})

app.delete('/users', auth, async(req, res) => {
    // A user can delete their profile as long as they are logged in with the jsonwebtoken
    try{
        await client.query('DELETE FROM users where email = $1',[req.user.email])
        res.status(200).send('Profile deleted')
        console.log('Profile deleted')
    }
    catch(e) {
        res.status(401).send(e.message)
    }
})

app.listen(port, () => {
    console.log(`Server is listening on port ${port}`)
})