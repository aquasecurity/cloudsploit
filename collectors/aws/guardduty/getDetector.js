var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var guardduty = new AWS.GuardDuty(AWSConfig);
    async.eachLimit(collection.guardduty.listDetectors[AWSConfig.region].data, 15, function(detectorId, cb) {
        collection.guardduty.getDetector[AWSConfig.region][detectorId] = {};
        var params = {
            'DetectorId': detectorId
        };

        guardduty.getDetector(params, function(err, data) {
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
