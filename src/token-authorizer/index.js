exports.handler = async (event, context, callback) => {
    
    const jwt = require('jsonwebtoken');
    const secretKey = "";
    
    if(!event.authorizationToken){
        callback("Unauthorized", null);
    }
    
    await jwt.verify(event.authorizationToken.replace('Bearer ', '')
        , secretKey
        , function(err, decoded) {
            if(err) {
                callback("Unauthorized", null);
            } else {
                var authResponse = buildAuthPolicy(event);
                callback(null, authResponse);
            }
        });
};

function buildAuthPolicy(event){
    const AuthPolicy = require('./AuthPolicy');
    var apiOptions = {};
    var tmp = event.methodArn.split(':');
    var apiGatewayArnTmp = tmp[5].split('/');
    var awsAccountId = tmp[4];
    apiOptions.region = tmp[3];
    apiOptions.restApiId = apiGatewayArnTmp[0];
    apiOptions.stage = apiGatewayArnTmp[1];
    var method = apiGatewayArnTmp[2];
    var resource = '/'; 
    if (apiGatewayArnTmp[3]) {
        resource += apiGatewayArnTmp.slice(3, apiGatewayArnTmp.length).join('/');
    }
    
    var policy = new AuthPolicy(null, awsAccountId, apiOptions);
    policy.allowAllMethods();
    var authResponse = policy.build();
    return authResponse;
}

// test
// exports.handler({
//     "type": "TOKEN",
//     "methodArn": "arn:aws:lambda:us-east-1:999999999999:function:another-lambdafunction/POST",
//     "authorizationToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE2MjUxNjI4OTEsImV4cCI6MTYyNTI0OTI5MSwiaWF0IjoxNjI1MTYyODkxfQ.iqwl3sXu4C0ourls_aBK6LNYvSyeyxkQ5jLLpRSeJXg"}
// , null
// , function(res, authResponse){console.log(authResponse)}
// );