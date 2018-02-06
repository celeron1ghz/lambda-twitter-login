'use strict';

const { OAuth } = require('oauth');
const vo        = require('vo');
const uniqid    = require('uniqid');
const Cookie    = require('cookie');
const aws       = require('aws-sdk');
const ssm       = new aws.SSM();
const dynamodb  = new aws.DynamoDB();


function getOAuthObject(event) {
  return vo(function*(){
    const host   = 'https://' + event.headers.Host + '/dev/callback'; // + event.requestContext.path;
    const key    = (yield ssm.getParameter({ Name: '/twitter_oauth/consumer_key',    WithDecryption: true }).promise() ).Parameter.Value;
    const secret = (yield ssm.getParameter({ Name: '/twitter_oauth/consumer_secret', WithDecryption: true }).promise() ).Parameter.Value;
    
    return new OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      key,
      secret,
      '1.0A',
      host,
      'HMAC-SHA1'
    );
  }).catch(err => {
    console.log("Error on creating oauth object:", err);
    throw err;
  })
}

module.exports.auth = (event, context, callback) => {
  vo(function*(){
    const uid   = Cookie.parse(event.headers.Cookie || '').sessid || uniqid();
    const oauth = yield getOAuthObject(event);

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
    const oauth  = yield getOAuthObject(event);

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

    callback(null, { statusCode: 200, body: "OK" });

  }).catch(err => {
    console.log("Error on callback:", err);
    callback(null, { statusCode: 200, body: "ERROR!" });
  })
};
