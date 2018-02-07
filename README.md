# lambda-twitter-login
Twitter OAuth login with serverless.


## SETUP
### PARAMETER
Set these value to `EC2 Parameter Store`.

 * `/twitter_oauth/consumer_key`: Twitter's consumer key
 * `/twitter_oauth/consumer_secret`: Twitter's consumer secret


### ENVIRONMENT VARIABLES
Set these value to environment variable.

 * `TWITTER_OAUTH_ORIGIN_URL`: client url (for cross domain access)


### SETUP SERVERLESS SCRIPT
```
git clone https://github.com/celeron1ghz/lambda-twitter-login.git
cd lambda-twitter-login
sls deploy
```


## SEE ALSO
 * https://github.com/celeron1ghz/lambda-twitter-login.git
 * https://github.com/abeyuya/serverless-auth.git
