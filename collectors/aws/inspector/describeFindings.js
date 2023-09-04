var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var inspector = new AWS.Inspector(AWSConfig);

    async.eachLimit(collection.inspector.listFindings[AWSConfig.region].data, 15, function(findingArn, cb) {
        collection.inspector.describeFindings[AWSConfig.region][findingArn] = {};

        var params = {
            findingArns: [findingArn]
        };

        helpers.makeCustomCollectorCall(inspector, 'describeFindings', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.inspector.describeFindings[AWSConfig.region][findingArn].err = err;
            }

            collection.inspector.describeFindings[AWSConfig.region][findingArn].data = data;
            cb();
        });
    }, function() {
        callback();
    });
};
