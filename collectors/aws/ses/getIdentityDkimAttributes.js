var AWS = require('aws-sdk');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ses = new AWS.SES(AWSConfig);
    collection.ses.getIdentityDkimAttributes[AWSConfig.region] = {};

    var identities = collection.ses.listIdentities[AWSConfig.region].data;
    var identityChunks = chunkArray(identities, 100);
    var allDkimAttributes = [];
    var processIdentityChunk = function(chunkIndex) {
        if (chunkIndex >= identityChunks.length) {
            collection.ses.getIdentityDkimAttributes[AWSConfig.region].data = {
                DkimAttributes: allDkimAttributes
            };
            callback();
            return;
        }

        var chunk = identityChunks[chunkIndex];
        var params = {
            Identities: chunk,
        };

        setTimeout(function() {
            helpers.makeCustomCollectorCall(ses, 'getIdentityDkimAttributes', params, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.ses.getIdentityDkimAttributes[AWSConfig.region].err = err;
                } else if (data && data.DkimAttributes) {
                    allDkimAttributes = {
                        ...allDkimAttributes,
                        ...data.DkimAttributes
                    };
                }
                processIdentityChunk(chunkIndex + 1);
            });
        }, 1000);
    };

    processIdentityChunk(0);
};
function chunkArray(arr, chunkSize) {
    var result = [];
    for (var i = 0; i < arr.length; i += chunkSize) {
        result.push(arr.slice(i, i + chunkSize));
    }
    return result;
}
