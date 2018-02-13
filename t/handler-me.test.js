'use strict';

const chai = require('chai');
const sinon = require('sinon');
const proxyquire = require('proxyquire');
const expect = require('chai').expect;
chai.use(require('chai-as-promised'));

describe('/me test', () => {
  let event;
  let callback;
  let lambda;
  let proxyDynamoDB;

  beforeEach(() => {
    event = { headers: { Cookie: null } };
    
    callback = (error, result) => new Promise((resolve, reject) => { error ? reject(error) : resolve(result) });

    proxyDynamoDB = class {
      getItem (params) {  return { promise: () => {} }  }
    };
    
    lambda = proxyquire('../handler', { 'aws-sdk': { DynamoDB: proxyDynamoDB } });
  });


  it('errors on no record found', () => {
    sinon
      .stub(proxyDynamoDB.prototype, 'getItem')
      .returns({
        promise: () => Promise.resolve({ Item: null })
      });
    
    return expect(lambda.me(event, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 500,
        body: JSON.stringify({ error: "LOGIN_EXPIRED" }),
      });
    });
  });


  it('errors on record is exist but login info is not exist', () => {
    sinon
      .stub(proxyDynamoDB.prototype, 'getItem')
      .returns({
        promise: () => Promise.resolve({ Item: {} })
      });
    
    return expect(lambda.me(event, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 500,
        body: JSON.stringify({ error: "NOT_LOGGED_IN" }),
      });
    });
  });


  it('ok', () => {
    sinon
      .stub(proxyDynamoDB.prototype, 'getItem')
      .returns({
        promise: () => Promise.resolve({ Item: { twitter_id:{S:"piyopiyo"}} })
      });
    
    process.env.TWITTER_OAUTH_ORIGIN_URL = "mogemogepiyopiyo"
    
    return expect(lambda.me(event, {}, callback)).to.be.fulfilled.then(result => {
      expect(result).to.deep.equal({
        statusCode: 200,
        headers: {
          "Access-Control-Allow-Credentials": true,
          "Access-Control-Allow-Origin": "mogemogepiyopiyo",
        },
        body: JSON.stringify({ twitter_id: "piyopiyo" }),
      });
    });
  }); 


  afterEach(() => {
    proxyDynamoDB.prototype.getItem.restore();
  });
});