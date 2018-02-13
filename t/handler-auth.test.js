'use strict';

const chai = require('chai');
const sinon = require('sinon');
const proxyquire = require('proxyquire');
const expect = require('chai').expect;
chai.use(require('chai-as-promised'));

describe('/auth test', () => {
  let event;
  let callback;
  let lambda;
  let proxyDynamoDB;
  let proxyOAuth;

  beforeEach(() => {
    event = { headers: { Cookie: null } };
    
    callback = (error, result) => new Promise((resolve, reject) => { error ? reject(error) : resolve(result) });

    proxyDynamoDB = class {
        putItem (params) { return { promise: () => {} }  }
    };

    proxyOAuth = class {
        createInstance (params) {  return { promise: () => {} }  }
    };
    
    lambda = proxyquire('../handler', {
      'aws-sdk': { DynamoDB: proxyDynamoDB },
      "./lib/TwitterOAuth":  proxyOAuth,
    });
  });
  

  it('ok', () => {
    sinon
      .stub(proxyDynamoDB.prototype, 'putItem')
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
    //proxyDynamoDB.prototype.putItem.restore();
  });
});