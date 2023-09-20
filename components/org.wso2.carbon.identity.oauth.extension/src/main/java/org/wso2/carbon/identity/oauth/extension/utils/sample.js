var connectionMetadata = {
    "url": "https://03ac6863-6825-4f92-b3f5-2b0cf9c25320-prod.e1-us-east-azure.choreoapis.dev/hvcc/test/endpoint-9090-803/1.0.0/testEchoAPI",
    "consumerKey": "j9nfX0smfW8nWxZctS_kmOBSndca",
    "consumerSecret": "0lN_vWrr70AxN4hWgFM3SMq6p7Ma",
    "tenantDomain": "vanheim"};

var requestPayload = {"example-key": "example-value"};
var idTokenAdditionalClaims = {};
var accessTokenAdditionalClaims = {};

var addToIDToken = function (jwtClaims,) {
    callChoreo(connectionMetadata, requestPayload, {
        onSuccess: function(data) {
            idTokenAdditionalClaims.att1 = "https://hello1.con";
        },
        onFail: function(data) {
            idTokenAdditionalClaims.att2 = "https://hello2.con";
        },
        onTimeout: function(data) {
            idTokenAdditionalClaims.att3 = "https://hello3.con";
        }
    });
};

var onPostLogin = function (context) {
    context.idToken.setAdditionalClaim("key","value");
};
