'use strict';

const chai = require('chai');
const sinon = require('sinon');
const proxyquire = require('proxyquire');
const expect = require('chai').expect;
chai.use(require('chai-as-promised'));

describe('/auth test', () => {
  const callback = (error, result) => new Promise((resolve, reject) => {
    error ? reject(error) : resolve(result)
  });

  let event;
  let lambda;
  let proxyDynamoDB;
  let proxyOAuth;

  beforeEach(() => {
    event = { headers: { Cookie: null } };
    proxyOAuth = class { createInstance () {} };
    proxyDynamoDB = class { put () {} };

    lambda = proxyquire('./handler', {
      'aws-sdk': { DynamoDB: { DocumentClient: proxyDynamoDB } },
      "./lib/TwitterOAuth":  proxyOAuth,
    });
  });


  it('ok', () => {
    sinon
      .stub(proxyDynamoDB.prototype, 'put')
      .returns({
        promise: () => Promise.resolve(null)
      });

    sinon
      .stub(proxyOAuth, 'createInstance')
      .returns(
        Promise.resolve({
          getOAuthRequestToken: () => Promise.resolve({
            oauth_token: "oauth_token", oauth_token_secret: "oauth_sec", results: {}
          })
        })
      );

    return expect(lambda.auth(event, {}, callback)).to.be.fulfilled.then(result => {
      const cookie = result.headers['Set-Cookie'];
      delete result.headers['Set-Cookie']

      expect(cookie).to.match(/^sessid=\w{17}$/);
      expect(result).to.deep.equal({
        statusCode: 200,
        headers: {},
        body: "https://twitter.com/oauth/authenticate?oauth_token=oauth_token",
      });
    });
  });


  afterEach(() => {
    proxyDynamoDB.prototype.put.restore();
  });
});