const jwt = require('jsonwebtoken')
const { Client } = require('pg')

// For ElephantSQL

const ElephSQLConStr = process.env.ESQL_URL
const client = new Client(ElephSQLConStr)

client.connect()

const auth = async (req, res, next) => {
    try{
        const token = req.header('Authorization').replace('Bearer ','')
        const decoded = jwt.verify(token,process.env.secret)
        const user = await client.query(`SELECT * FROM users WHERE email=$1 AND tokens = $2`,[decoded.pass,[token]])

        if(user.rowCount === 0) {
            throw Error('Issue with authentication')
        }
        req.user = user.rows[0]
        auth_token = token
        next()
    }
    catch(e) {
        console.log(e)
        res.status(401).send('Authentication Failed')
    }
}

module.exports = auth