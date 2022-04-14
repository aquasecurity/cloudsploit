var AWS = require('aws-sdk');
// var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ses = new AWS.SES(AWSConfig);

    let identities = collection.ses.listIdentities[AWSConfig.region].data;
    const chunk = (identities, size) =>
    Array.from({ length: Math.ceil(identities.length / size) }, (v, i) =>
        identities.slice(i * size, i * size + size)
    );

    let arr = chunk(identities, 100);
    
    for (let entry of arr) {

        collection.ses.getIdentityVerificationAttributes[AWSConfig.region] = {};
        
        var params = {
            Identities: entry
        };

        helpers.makeCustomCollectorCall(ses, 'getIdentityVerificationAttributes', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.ses.getIdentityVerificationAttributes[AWSConfig.region].err = err;
            } else {
                collection.ses.getIdentityVerificationAttributes[AWSConfig.region].data = data;
            }
        });

    }
        callback();
};

        


