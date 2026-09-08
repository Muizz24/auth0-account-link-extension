// Integration tests for the account linking extension.
// These tests use nock to intercept all Auth0 Management API calls so no real
// tenant or credentials are required. They test the two core user-facing flows:
//   1. Link — extension renders linking template with correct user context
//   2. Skip — extension renders template (skip is a client-side /continue redirect)
// Error cases cover invalid tokens and upstream API failures.

const { expect } = require('chai');
const nock = require('nock');
const sinon = require('sinon');
const { sign } = require('jsonwebtoken');
const { createServer } = require('../test/test_helper');
const storage = require('../lib/storage');
const indexTemplate = require('../templates');
const linkingJwtUtils = require('../lib/linkingJwtUtils');
const config = require('../lib/config');

// Config provider is set by createServer() in before() — these are
// populated then and safe to use in beforeEach/it blocks after that.
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

const mockUsers = () => {
  sinon.stub(linkingJwtUtils, 'fetchUsersFromToken').resolves({
    currentUser: primaryUser,
    matchingUsers: [secondaryUser],
  });
};

describe('Account linking integration', function () {
  let server;

  before(async function () {
    server = await createServer();
    DOMAIN = config('AUTH0_DOMAIN');
    CLIENT_ID = config('AUTH0_CLIENT_ID');
    CLIENT_SECRET = config('AUTH0_CLIENT_SECRET');
    ISSUER = `https://${DOMAIN}/`;
  });

  after(function () {
    server.stop();
  });

  beforeEach(function () {
    nock.cleanAll();
    sinon.restore();
    sinon.stub(storage, 'getSettings').resolves({ customDomain: '' });
    sinon.stub(storage, 'getLocales').resolves({ en: { or: 'or' } });
    sinon.stub(indexTemplate, 'renderTemplate').resolves('<html>Mock Template</html>');
    mockUsers();
  });

  afterEach(function () {
    nock.cleanAll();
    sinon.restore();
  });

  describe('link flow', function () {
    it('returns 200 and renders the linking template', async function () {
      const res = await server.inject({
        method: 'GET',
        url: `/?${makeQueryString(makeChildToken(primaryUser))}`,
      });

      expect(res.statusCode).to.equal(200);
      expect(res.result).to.equal('<html>Mock Template</html>');
    });

    it('passes currentUser and matchingUsers correctly to renderTemplate', async function () {
      await server.inject({
        method: 'GET',
        url: `/?${makeQueryString(makeChildToken(primaryUser))}`,
      });

      const { currentUser, matchingUsers } = indexTemplate.renderTemplate.args[0][0];
      expect(currentUser.user_id).to.equal(primaryUser.user_id);
      expect(matchingUsers).to.have.length(1);
      expect(matchingUsers[0].user_id).to.equal(secondaryUser.user_id);
    });
  });

  describe('skip flow', function () {
    it('returns 200 and renders the template', async function () {
      // Skipping is a client-side navigation — the skip anchor in the rendered
      // HTML points to `{issuer}continue?state={state}`. The server always
      // returns 200 with the template regardless of whether the user links or skips.
      const res = await server.inject({
        method: 'GET',
        url: `/?${makeQueryString(makeChildToken(primaryUser))}`,
      });

      expect(res.statusCode).to.equal(200);
      expect(res.result).to.equal('<html>Mock Template</html>');
    });

    it('includes state in the rendered output for the skip redirect', async function () {
      const state = 'skip-test-state-789';
      await server.inject({
        method: 'GET',
        url: `/?${makeQueryString(makeChildToken(primaryUser), { state })}`,
      });

      const { params } = indexTemplate.renderTemplate.args[0][0];
      expect(params.state).to.equal(state);
    });
  });

  describe('error cases', function () {
    it('redirects to /admin when no query parameters are provided', async function () {
      const res = await server.inject({ method: 'GET', url: '/' });
      expect(res.statusCode).to.equal(302);
      expect(res.headers.location).to.include('/admin');
    });

    it('returns 400 when an invalid child_token is provided', async function () {
      const res = await server.inject({
        method: 'GET',
        url: `/?${makeQueryString('not-a-valid-jwt')}`,
      });
      expect(res.statusCode).to.equal(400);
    });

    it('redirects to /continue when users-by-email lookup fails', async function () {
      // Override the default stub to simulate an upstream failure
      linkingJwtUtils.fetchUsersFromToken.rejects(new Error('upstream failure'));

      const res = await server.inject({
        method: 'GET',
        url: `/?${makeQueryString(makeChildToken(primaryUser))}`,
      });

      expect(res.statusCode).to.equal(302);
      expect(res.headers.location).to.include('continue?state=');
    });
  });
});
