# lambda-twitter-login-session
Twitter OAuth login with serverless and session.


## SETUP
### PARAMETER
Set these value to `EC2 Parameter Store`.

 * `/twitter_oauth/consumer_key`: Twitter's consumer key
 * `/twitter_oauth/consumer_secret`: Twitter's consumer secret


### ENVIRONMENT VARIABLES
Set these value to environment variable.

In this case, assume these setting:
 * API provide in `auth.example.com`
 * Client access from `https://local.example.net`

#### TWITTER_OAUTH_ORIGIN_URL
Client domain name.

e.g.) `https://local.example.net`

#### TWITTER_OAUTH_ACM_CERTIFICATE_ARN
ARN of ACM's certificate.

e.g.) `arn:aws:acm:us-east-1:000000000000:certificate/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

NOTE:
  * ACM certificate should get in `us-east-1` region. this is AWS's restriction.
  * ACM's domain should be as `*.example.com`

#### TWITTER_OAUTH_ACM_FQDN
API domain name.

e.g.) `auth.example.com`

#### TWITTER_OAUTH_ACM_DOMAIN
Domain of serve. Same as `TWITTER_OAUTH_ACM_CERTIFICATE_ARN`'s domain.

e.g.) `example.com`


### SETUP SERVERLESS SCRIPT
```
git clone https://github.com/celeron1ghz/lambda-twitter-login.git
cd lambda-twitter-login
sls deploy
```


## SEE ALSO
 * https://github.com/celeron1ghz/lambda-twitter-login.git
 * https://github.com/abeyuya/serverless-auth.git
