var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var guardduty = new AWS.GuardDuty(AWSConfig);
    async.eachLimit(collection.guardduty.listDetectors[AWSConfig.region].data, 15, function(detectorId, dcb) {
        const findingIds = collection.guardduty.listDetectors[AWSConfig.region].data[detectorId];
        if (!findingIds) dcb();
        collection.guardduty.getFindings[AWSConfig.region][detectorId] = {};
        const params = {
            DetectorId: detectorId,
            FindingIds: findingIds
        };
        guardduty.getFindings(params, function(err, data) {
            if (err) {
                collection.guardduty.getFindings[AWSConfig.region][detectorId].err = err;
            }
            collection.guardduty.getFindings[AWSConfig.region][detectorId].data = data;
            dcb();
        });
       
    }, function(){
        callback();
    });
};
