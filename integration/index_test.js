const puppeteer = require('puppeteer');
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

const nockMgmtToken = () =>
  nock(`https://${DOMAIN}`)
    .post('/oauth/token', {
      audience: `https://${DOMAIN}/api/v2/`,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'client_credentials',
    })
    .reply(200, { access_token: 'mock-mgmt-token', token_type: 'Bearer', expires_in: 86400 });

const nockUsersByEmail = (users, email = primaryUser.email) =>
  nock(`https://${DOMAIN}`)
    .get('/api/v2/users-by-email')
    .query({ email })
    .reply(200, users);

describe('Account linking tests', function () {
  let server, browser, page, baseUrl;

  before(async function () {
    server = await createServer();
    DOMAIN = config('AUTH0_DOMAIN');
    CLIENT_ID = config('AUTH0_CLIENT_ID');
    CLIENT_SECRET = config('AUTH0_CLIENT_SECRET');
    ISSUER = `https://${DOMAIN}/`;

    await server.start();
    baseUrl = server.info.uri;

    browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  });

  after(async function () {
    if (browser) await browser.close();
    if (server) await server.stop();
    nock.cleanAll();
  });

  beforeEach(async function () {
    page = await browser.newPage();
  });

  afterEach(async function () {
    if (page) await page.close();
    expect(nock.pendingMocks()).to.be.empty;
    nock.cleanAll();
  });

  it('renders link and skip buttons when duplicate email detected', async function () {
    nockMgmtToken();
    nockUsersByEmail([primaryUser, secondaryUser]);

    await page.goto(`${baseUrl}/?${makeQueryString(makeChildToken(primaryUser))}`, {
      waitUntil: 'networkidle0',
    });

    await page.waitForSelector('#link');

    const linkDisabled = await page.$eval('#link', (el) => el.disabled);
    const skipHref = await page.$eval('#skip', (el) => el.getAttribute('href'));
    const messageText = await page.$eval('#message', (el) => el.textContent);

    expect(linkDisabled).to.be.false;
    expect(skipHref).to.include(`continue?state=test-state-123`);
    expect(messageText).to.include('It looks like you have another account');
  });

  it('navigates to authorize with correct params when link is clicked', async function () {
    nockMgmtToken();
    nockUsersByEmail([primaryUser, secondaryUser]);

    await page.setRequestInterception(true);

    const authorizeUrlPromise = new Promise((resolve) => {
      page.on('request', (req) => {
        const url = req.url();
        if (url.includes('/authorize?')) {
          req.abort();
          resolve(url);
        } else {
          req.continue();
        }
      });
    });

    await page.goto(`${baseUrl}/?${makeQueryString(makeChildToken(primaryUser))}`, {
      waitUntil: 'networkidle0',
    });

    await page.waitForSelector('#link');
    await page.click('#link').catch(() => {});
    const authorizeUrl = await authorizeUrlPromise;

    expect(authorizeUrl).to.include('/authorize?');
    const params = new URL(authorizeUrl).searchParams;
    expect(params.get('link_account_token')).to.be.a('string').and.not.be.empty;
    expect(params.get('connection')).to.equal('google-oauth2');
    expect(params.get('client_id')).to.equal(CLIENT_ID);
  });

  it('disables link button and shows error message when invalid token provided', async function () {
    await page.goto(`${baseUrl}/?${makeQueryString('not-a-valid-jwt')}`, {
      waitUntil: 'networkidle0',
    });

    await page.waitForSelector('#link');

    const linkDisabled = await page.$eval('#link', (el) => el.disabled);
    const containerText = await page.$eval('#content-container', (el) => el.textContent.trim());

    expect(linkDisabled).to.be.true;
    expect(containerText).to.include('You seem to have reached this page in error');
  });

  it('shows error message when upstream API fails', async function () {
    nockMgmtToken();
    nock(`https://${DOMAIN}`)
      .get('/api/v2/users-by-email')
      .query({ email: primaryUser.email })
      .reply(500, { error: 'server_error', message: 'Internal server error' });

    await page.goto(`${baseUrl}/?${makeQueryString(makeChildToken(primaryUser))}`, {
      waitUntil: 'networkidle0',
    });

    await page.waitForSelector('#content-container');
    const containerText = await page.$eval('#content-container', (el) => el.textContent.trim());
    expect(containerText).to.include('You seem to have reached this page in error');
  });
});
