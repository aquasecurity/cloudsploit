var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ses = new AWS.SES(AWSConfig);

    if (!collection.ses ||
        !collection.ses.listIdentities ||
        !collection.ses.listIdentities[AWSConfig.region] ||
        !collection.ses.listIdentities[AWSConfig.region].data) return callback();

    let identities = collection.ses.listIdentities[AWSConfig.region].data;
    const chunk = (identities, size) => Array.from({ length: Math.ceil(identities.length / size) }, (v, i) =>
        identities.slice(i * size, i * size + size)
    );

    let identityArr = chunk(identities, 2);
    collection.ses.getIdentityVerificationAttributes[AWSConfig.region] = {};

    async.eachLimit(identityArr, 1, (entry, cb) => {
        
        var params = {
            Identities: entry
        };

        setTimeout(() => {
            helpers.makeCustomCollectorCall(ses, 'getIdentityVerificationAttributes', params, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.ses.getIdentityVerificationAttributes[AWSConfig.region].err = err;
                } else {
                    if (data && data.VerificationAttributes &&
                        collection.ses.getIdentityVerificationAttributes[AWSConfig.region].data &&    
                        collection.ses.getIdentityVerificationAttributes[AWSConfig.region].data.VerificationAttributes) {
                        collection.ses.getIdentityVerificationAttributes[AWSConfig.region].data.VerificationAttributes = { ...collection.ses.getIdentityVerificationAttributes[AWSConfig.region].data.VerificationAttributes, ...data.VerificationAttributes};
                    } else {
                        collection.ses.getIdentityVerificationAttributes[AWSConfig.region].data = data;
                    }
                }
                cb();
            });
        }, 1000);
    }, function(){
        callback();
    });
};

        


