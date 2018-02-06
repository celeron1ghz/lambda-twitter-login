'use strict';

const TwitterOAuth = require('./lib/TwitterOAuth');

const vo        = require('vo');
const uniqid    = require('uniqid');
const Cookie    = require('cookie');
const aws       = require('aws-sdk');
const dynamodb  = new aws.DynamoDB();

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
