const crypto = require('crypto')

// This function hashes user password before storing in the database
const hash = (password) => {

    var hash = crypto.createHash('sha256')
    const data = hash.update(password, 'utf-8')
    const gen_hash = data.digest('hex')
    return gen_hash
}

module.exports = {hash}