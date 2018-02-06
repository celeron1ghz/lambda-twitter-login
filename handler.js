'use strict';

const { OAuth } = require('oauth');
const vo        = require('vo');
const uniqid    = require('uniqid');
const Cookie    = require('cookie');
const aws       = require('aws-sdk');
const ssm       = new aws.SSM();
const dynamodb  = new aws.DynamoDB();

class TwitterOAuth {
  static createInstance(event){
    return vo(function*(){
      const key    = (yield ssm.getParameter({ Name: '/twitter_oauth/consumer_key',    WithDecryption: true }).promise() ).Parameter.Value;
      const secret = (yield ssm.getParameter({ Name: '/twitter_oauth/consumer_secret', WithDecryption: true }).promise() ).Parameter.Value;
      return new TwitterOAuth(event, key, secret);
    }).catch(err => {
      console.log("Error on creating oauth object:", err);
      throw err;
    })
  }

  constructor(event, key, secret) {
    this.oauth = new OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      key,
      secret,
      '1.0A',
      'https://' + event.headers.Host + '/dev/callback', // + event.requestContext.path
      'HMAC-SHA1'
    );
  }

  getOAuthRequestToken() {
    return new Promise((resolve, reject) => {
      this.oauth.getOAuthRequestToken((error, oauth_token, oauth_token_secret, results) => {
        if (error) { reject(error) }
        else       { resolve({ oauth_token, oauth_token_secret, results })  }
      });
    });
  }

  getOAuthAccessToken(token, secret, verifier) {
    return new Promise((resolve,reject) => {
      this.oauth.getOAuthAccessToken(token, secret, verifier, (error, access_token, access_token_secret, results) => {
        if (error) { reject(error) }
        else       { resolve({ access_token, access_token_secret, results })  }
      });
    })
  }
}

module.exports.auth = (event, context, callback) => {
  vo(function*(){
    const uid   = Cookie.parse(event.headers.Cookie || '').sessid || uniqid();
    const oauth = yield TwitterOAuth.createInstance(event);
    const auth  = yield oauth.getOAuthRequestToken();

    yield dynamodb.updateItem({
      Key:                       { "uid": {S:uid} }, 
      ExpressionAttributeNames:  { "#session": "session", "#ttl": "ttl" }, 
      ExpressionAttributeValues: { ":value": {S:auth.oauth_token_secret}, ":ttl": {N:(new Date().getTime() / 1000 + 60 * 24) + ""} }, 
      ReturnValues: "ALL_NEW", 
      TableName: "twitter_oauth", 
      UpdateExpression: "SET #session = :value, #ttl = :ttl"
    }).promise()

    callback(null, {
      statusCode: 200,
      body:       'https://twitter.com/oauth/authenticate?oauth_token=' + auth.oauth_token,
      headers:    { 'Set-Cookie': 'sessid=' + uid },
    });

  }).catch(err => {
    console.log("Error on auth:", err);
    callback(null, { statusCode: 200, body: "ERROR!" });
  })
};

module.exports.callback = (event, context, callback) => {
  vo(function*(){
    const query  = event.queryStringParameters;
    const sessid = Cookie.parse(event.headers.Cookie || '').sessid;
    const oauth  = yield TwitterOAuth.createInstance(event);
    const row    = yield dynamodb.getItem({ TableName: "twitter_oauth", Key: { "uid": {S:sessid} } }).promise();
    
    if (!row.Item) {
      throw new Error("Record not found for sessid=" + sessid)
    }
    
    const oauth_token_secret = row.Item.session.S;
    const ret = yield oauth.getOAuthAccessToken(query.oauth_token, oauth_token_secret, query.oauth_verifier);
    
    console.log(ret);
    callback(null, { statusCode: 200, body: "OK" });

  }).catch(err => {
    console.log("Error on callback:", err);
    callback(null, { statusCode: 200, body: "ERROR!" });
  })
};
