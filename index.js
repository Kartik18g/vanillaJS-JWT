const {
    createHmac,
} = require('crypto');



const encodeToBase64 = (data) => {
    const buf = Buffer.from(data, 'utf8');
    var base64WithPadding = buf.toString('base64')
    var base64WithoutPadding = base64WithPadding.replace(/=+$/, "");

    // Replace characters according to base64url specifications
    base64WithoutPadding = base64WithoutPadding.replace(/\+/g, "-");
    base64WithoutPadding = base64WithoutPadding.replace(/\//g, "_");
    return base64WithoutPadding
}


const generateSignature = (data, secret) => {
    var hash = createHmac('SHA256', secret).update(data).digest('base64');
    var encodedHash = hash.replace(/=+$/, "");
    // Replace characters according to base64url specifications
    encodedHash = encodedHash.replace(/\+/g, "-");
    encodedHash = encodedHash.replace(/\//g, "_");
    return encodedHash

}

const generateJWT = (data, header, secret) => {
    var d = new Date()

    const payload = {
        "iat": Math.floor(d.getTime() / 1000),
        "nbf": Math.floor(d.getTime() / 1000),
        "exp": Math.floor(d.getTime() / 1000) + 3600,
        "aud": "RocketChat",
        "context": data
    }

    const encodedPayload = encodeToBase64(JSON.stringify(payload))
    const encodedHeader = encodeToBase64(JSON.stringify(header))
    const encodedSignature = generateSignature(`${encodedHeader}.${encodedPayload}`, secret)
    const JWT = `${encodedHeader}.${encodedPayload}.${encodedSignature}`
    return JWT
}

