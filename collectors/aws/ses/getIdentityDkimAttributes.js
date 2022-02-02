var AWS = require('aws-sdk');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ses = new AWS.SES(AWSConfig);

    helpers.makeCustomCollectorCall(ses, 'getIdentityDkimAttributes', {Identities: collection.ses.listIdentities[AWSConfig.region].data}, retries, null, null, null, function(err, data) {
        if (err) {
            collection.ses.getIdentityDkimAttributes[AWSConfig.region].err = err;
        }

        collection.ses.getIdentityDkimAttributes[AWSConfig.region].data = data;

        callback();
    });
};