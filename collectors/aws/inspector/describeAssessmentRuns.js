var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var inspector = new AWS.Inspector(AWSConfig);

    async.eachLimit(collection.inspector.listAssessmentRuns[AWSConfig.region].data, 15, function(runArn, cb) {
        collection.inspector.describeAssessmentRuns[AWSConfig.region][runArn] = {};

        var params = {
            assessmentRunArns: [runArn]
        };

        helpers.makeCustomCollectorCall(inspector, 'describeAssessmentRuns', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.inspector.describeAssessmentRuns[AWSConfig.region][runArn].err = err;
            }

            collection.inspector.describeAssessmentRuns[AWSConfig.region][runArn].data = data;
            cb();
        });
    }, function() {
        callback();
    });
};
