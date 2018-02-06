'use strict';

const { OAuth } = require('oauth');
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

module.exports = TwitterOAuth;