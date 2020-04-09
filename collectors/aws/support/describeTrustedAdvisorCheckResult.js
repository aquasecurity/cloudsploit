var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var support = new AWS.Support(AWSConfig);

    async.eachLimit(collection.support.describeTrustedAdvisorChecks[AWSConfig.region].data, 15, function(check, cb) {
        collection.support.describeTrustedAdvisorChecks[AWSConfig.region][check] = {};

        var params = {
            checkId: check,
        };

        support.describeTrustedAdvisorCheckResult(params, function(err, data) {
            if (err) {
                collection.support.describeTrustedAdvisorChecks[AWSConfig.region][check].err = err;
            }
            collection.support.describeTrustedAdvisorChecks[AWSConfig.region][check].data = data;
            cb();
        });
    }, function() {
        callback();
    });
};
