var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var guardduty = new AWS.GuardDuty(AWSConfig);
    async.eachLimit(collection.guardduty.listDetectors[AWSConfig.region].data, 15, function(detectorId, cb) {
        collection.guardduty.getDetector[AWSConfig.region][detectorId] = {};
        var params = {
            'DetectorId': detectorId
        };

        helpers.makeCustomCollectorCall(guardduty, 'getDetector', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.guardduty.getDetector[AWSConfig.region][detectorId].err = err;
            }
            collection.guardduty.getDetector[AWSConfig.region][detectorId].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
