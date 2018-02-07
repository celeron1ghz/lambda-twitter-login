'use strict';

const OAuth   = require('oauth').OAuth;
const Twitter = require('twitter');

const aws = require('aws-sdk');
const ssm = new aws.SSM();
const vo  = require('vo');

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
    this.consumer_key    = key;
    this.consumer_secret = secret;

    // fix path for aws's auto-assigned URL and mydomain
    const innerPath = event.path;
    const outerPath = event.requestContext.path;
    const cbPath    = outerPath.replace(innerPath, "/callback");

    this.oauth = new OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      key,
      secret,
      '1.0A',
      'https://' + event.headers.Host + cbPath,
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

  call_get_api(token, token_secret, path, param) {
    const client = new Twitter({
      consumer_key:         this.consumer_key,
      consumer_secret:      this.consumer_secret,
      access_token_key:     token,
      access_token_secret:  token_secret,
    });

    return client.get(path, param);
  }
}

module.exports = TwitterOAuth;