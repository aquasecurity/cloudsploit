var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var support = new AWS.Support(AWSConfig);

    async.eachLimit(collection.support.describeTrustedAdvisorChecks[AWSConfig.region].data, 15, function(check, cb) {
        collection.support.describeTrustedAdvisorChecks[AWSConfig.region][check] = {};

        var params = {
            checkId: check,
        };

        helpers.makeCustomCollectorCall(support, 'describeTrustedAdvisorCheckResult', params, retries, null, null, null, function(err, data) {
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
