'use strict';

const { OAuth } = require('oauth');
const vo        = require('vo');
const uniqid    = require('uniqid');
const Cookie    = require('cookie');
const aws       = require('aws-sdk');
const ssm       = new aws.SSM();
const dynamodb  = new aws.DynamoDB();

module.exports.auth = (event, context, callback) => {
  vo(function*(){
    const uid             = Cookie.parse(event.headers.Cookie || '').sessid || uniqid();
    const host            = event.headers.Host; // + event.requestContext.path;
    const consumer_key    = (yield ssm.getParameter({ Name: '/twitter_oauth/consumer_key',    WithDecryption: true }).promise() ).Parameter.Value;
    const consumer_secret = (yield ssm.getParameter({ Name: '/twitter_oauth/consumer_secret', WithDecryption: true }).promise() ).Parameter.Value;
    const oauth           = new OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      consumer_key,
      consumer_secret,
      '1.0A',
      'https://' + host + '/dev/callback',
      'HMAC-SHA1'
    );

    const auth = yield new Promise((resolve, reject) => {
      oauth.getOAuthRequestToken((error, oauth_token, oauth_token_secret, results) => {
        if (error) { reject(error) }
        else       { resolve({ oauth_token, oauth_token_secret, results })  }
      });
    });

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
      body:       JSON.stringify({ url: 'https://twitter.com/oauth/authenticate?oauth_token=' + auth.oauth_token }),
      headers:    { 'Set-Cookie': 'sessid=' + uid },
    });

  }).catch(err => {
    console.log("Error on auth:", err);
    callback(null, { statusCode: 200, body: "ERROR!" });
  })
};

module.exports.callback = (event, context, callback) => {
  vo(function*(){
    const query           = event.queryStringParameters;
    const sessid          = Cookie.parse(event.headers.Cookie || '').sessid;
    
    const consumer_key    = (yield ssm.getParameter({ Name: '/twitter_oauth/consumer_key',    WithDecryption: true }).promise() ).Parameter.Value;
    const consumer_secret = (yield ssm.getParameter({ Name: '/twitter_oauth/consumer_secret', WithDecryption: true }).promise() ).Parameter.Value;

    const oauth = new OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      consumer_key,
      consumer_secret,
      '1.0A',
      null,
      'HMAC-SHA1'
    );
    
    const row = yield dynamodb.getItem({ TableName: "twitter_oauth", Key: { "uid": {S:sessid} } }).promise();
    
    if (!row.Item) {
      throw new Error("Record not found for sessid=" + sessid)
    }
    
    const oauth_token_secret = row.Item.session.S;
    
    const ret = yield new Promise((resolve,reject) => {
      oauth.getOAuthAccessToken(query.oauth_token, oauth_token_secret, query.oauth_verifier,
        function(error, access_token, access_token_secret, results){
          if (error) { reject(error) }
          else       { resolve({ access_token, access_token_secret, results })  }
        }
      );
    })

    console.log(ret);

    callback(null, { statusCode: 200, body: JSON.stringify({ message: "OK" }) });

  }).catch(err => {
    console.log("Error on callback:", err);
    callback(null, { statusCode: 200, body: "ERROR!" });
  })
};
