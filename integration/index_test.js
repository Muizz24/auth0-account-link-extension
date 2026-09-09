const { expect } = require('chai');
const nock = require('nock');
const { sign } = require('jsonwebtoken');
const { createServer } = require('../test/test_helper');
const config = require('../lib/config');

let DOMAIN, CLIENT_ID, CLIENT_SECRET, ISSUER;

const primaryUser = {
  user_id: 'auth0|primary001',
  email: 'jane.doe@example.com',
  email_verified: true,
  identities: [{ connection: 'Username-Password-Authentication', user_id: 'primary001', provider: 'auth0', isSocial: false }],
  created_at: '2024-01-01T00:00:00.000Z',
};

const secondaryUser = {
  user_id: 'auth0|secondary001',
  email: 'jane.doe@example.com',
  email_verified: true,
  identities: [{ connection: 'google-oauth2', user_id: 'secondary001', provider: 'google-oauth2', isSocial: true }],
  created_at: '2024-01-02T00:00:00.000Z',
};

const makeChildToken = (user) =>
  sign(
    { sub: user.user_id, email: user.email },
    CLIENT_SECRET,
    { audience: CLIENT_ID, issuer: ISSUER, expiresIn: '5m' }
  );

const makeQueryString = (childToken, overrides = {}) => {
  const params = {
    child_token: childToken,
    client_id: CLIENT_ID,
    redirect_uri: 'http://localhost:3000/callback',
    scope: 'openid profile',
    response_type: 'code',
    state: 'test-state-123',
    original_state: 'test-original-state-456',
    nonce: 'test-nonce',
    ...overrides,
  };
  return new URLSearchParams(params).toString();
};

const nockManagementToken = () =>
  nock(`https://${DOMAIN}`)
    .post('/oauth/token', {
      audience: `https://${DOMAIN}/api/v2/`,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'client_credentials',
    })
    .reply(200, { access_token: 'mock-mgmt-token', token_type: 'Bearer', expires_in: 86400 });

const nockUsersByEmail = (users) =>
  nock(`https://${DOMAIN}`)
    .get('/api/v2/users-by-email')
    .query({ email: primaryUser.email })
    .reply(200, users);

describe('Account linking tests', function () {
  let server;

  before(async function () {
    server = await createServer();
    DOMAIN = config('AUTH0_DOMAIN');
    CLIENT_ID = config('AUTH0_CLIENT_ID');
    CLIENT_SECRET = config('AUTH0_CLIENT_SECRET');
    if (!CLIENT_SECRET) throw new Error('before(): AUTH0_CLIENT_SECRET not configured');
    ISSUER = `https://${DOMAIN}/`;
    nock.disableNetConnect();
  });

  after(async function () {
    if (server) await server.stop();
    nock.enableNetConnect();
  });

  afterEach(function () {
    nock.cleanAll();
  });

  it('detects repeated email and links account', async function () {
    nockManagementToken();
    nockUsersByEmail([primaryUser, secondaryUser]);

    const res = await server.inject({
      method: 'GET',
      url: `/?${makeQueryString(makeChildToken(primaryUser))}`,
    });

    expect(res.statusCode).to.equal(200);
    expect(res.result).to.include('It looks like you have another account with the same email address');
  });

  it('skips linking', async function () {
    nockManagementToken();
    nockUsersByEmail([primaryUser, secondaryUser]);
    // Set up a nock for identity linking but assert it is never called —
    // skipping is a client-side /continue redirect, not a server-side API call
    const identityLinkScope = nock(`https://${DOMAIN}`)
      .post(/\/api\/v2\/users\/.*\/identities/)
      .reply(201, []);

    const state = 'test-state-123';
    const res = await server.inject({
      method: 'GET',
      url: `/?${makeQueryString(makeChildToken(primaryUser), { state })}`,
    });

    expect(res.statusCode).to.equal(200);
    expect(res.result).to.include(`"state":"${state}"`);
    expect(identityLinkScope.isDone()).to.equal(false);
  });

  it('shows an error when invalid token is provided', async function () {
    const res = await server.inject({
      method: 'GET',
      url: `/?${makeQueryString('not-a-valid-jwt')}`,
    });

    expect(res.statusCode).to.equal(400);
    expect(res.result).to.include('You seem to have reached this page in error. Please try logging in again');
  });

  it('shows an error when no parameters are provided', async function () {
    const res = await server.inject({ method: 'GET', url: '/' });

    expect(res.statusCode).to.equal(302);
    expect(res.headers.location).to.include('/admin');
  });
});
