const crypto = require('crypto')

const hash = (password) => {

    var hash = crypto.createHash('sha256')
    const data = hash.update(password, 'utf-8')
    const gen_hash = data.digest('hex')
    return gen_hash
}

module.exports = {hash}