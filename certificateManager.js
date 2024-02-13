import acme from 'acme-client'
import forge from 'node-forge'
import tls from 'tls'

const HTTP_01_TOKENS = {}
const SECURE_CONTEXTS = {}
const ONE_DAY_IN_MS = 1000 * 60 * 60 * 24

export function getToken (req, res) {
  const token = HTTP_01_TOKENS[req.url]
  console.log('req');
  console.log(req.url);
  console.log(HTTP_01_TOKENS);
  console.log(HTTP_01_TOKENS[req.url]);
  console.log(token);

  let status
  let text
  if (token) {
    status = 200
    text = token
  } else {
    status = 404
    text = 'Not found'
  }

  console.log(status + '_' + text);
  res.writeHead(status, { 'Content-Type': 'text/plain' })
  res.end(text)
}

function createSecureContext (domain, credentials) {
  SECURE_CONTEXTS[domain] = tls.createSecureContext(credentials)
}

export async function getSecureContext (domain) {
  return SECURE_CONTEXTS[domain]
}

async function validateCertificate (certificate) {
  const certificateObject = forge.pki.certificateFromPem(certificate)
  const expirationDate = certificateObject.validity.notAfter

  const currentDate = new Date()
  const timeDiff = expirationDate.getTime() - currentDate.getTime()
  const daysUntilExpiration = Math.ceil(timeDiff / ONE_DAY_IN_MS)

  return daysUntilExpiration >= 3
}

async function createOrUpdateCertificate (domain) {
  try {
    // acme.setLogger(console.log)
    const client = new acme.Client({
      directoryUrl: process.env.NODE_ENV === 'production' ? acme.directory.letsencrypt.production : acme.directory.letsencrypt.staging,
      accountKey: await acme.crypto.createPrivateKey()
    })

    const [key, csr] = await acme.crypto.createCsr({ commonName: domain })

    const autoParams = {
      csr,
      termsOfServiceAgreed: true,
      challengeCreateFn: async (authz, challenge, keyAuthorization) => {
        if (challenge.type === 'http-01') {
          console.log('challengeCreateFn');
          console.log(challenge.token);
          console.log(keyAuthorization);
          HTTP_01_TOKENS[`/.well-known/acme-challenge/${challenge.token}`] = keyAuthorization
          console.log(HTTP_01_TOKENS);
        } else if (challenge.type === 'dns-01') {
          console.log('certificateManager: dns-01 challenge is not supported')
        }
      },
      challengeRemoveFn: async (authz, challenge) => {
        if (challenge.type === 'http-01') {
          console.log('challengeRemoveFn');
          delete HTTP_01_TOKENS[`/.well-known/acme-challenge/${challenge.token}`]
        } else if (challenge.type === 'dns-01') {
          console.log('certificateManager: dns-01 challenge is not supported')
        }
      }
    }

    let cert
    try {
      // NEED TO TEST RETURN TYPE
      const autoRes = await client.auto(autoParams)
      cert = autoRes.cert
      console.log('AUTO RES!!!');
      console.log(autoRes);
      console.log(cert);
    } catch (err) {
      console.log('failed to refresh TLS certificate')
      console.log(err);
    }

    if (!cert) {
      return
    }

    createSecureContext(domain, { cert, key })

  } catch (err) {
    console.log(`failed to refresh TLS certificate for ${domain} `, err)
  }
}

async function handleDomains (domains) {
  for (const domain of domains) {
    await createOrUpdateCertificate(domain)
  }
}

export function init () {
  const domains = process.env.HTTPS_DOMAINS?.split?.(',')
  // const domains = ['fc7b-46-246-41-172.ngrok-free.app']
  if (!domains?.length) return

  setInterval(() => {
    handleDomains(domains)
  }, ONE_DAY_IN_MS)

  handleDomains(domains)
}
