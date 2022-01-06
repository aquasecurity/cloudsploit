var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var guardduty = new AWS.GuardDuty(AWSConfig);
    async.eachLimit(collection.guardduty.listDetectors[AWSConfig.region].data, 15, function(detectorId, dcb) {
        if (!collection.guardduty ||
            !collection.guardduty.listFindings ||
            !collection.guardduty.listFindings[AWSConfig.region] ||
            !collection.guardduty.listFindings[AWSConfig.region][detectorId] ||
            !collection.guardduty.listFindings[AWSConfig.region][detectorId].data ||
            !collection.guardduty.listFindings[AWSConfig.region][detectorId].data.FindingIds) return dcb();

        const findingIds = collection.guardduty.listFindings[AWSConfig.region][detectorId].data.FindingIds;

        if (!findingIds || !findingIds.length) return dcb();

        collection.guardduty.getFindings[AWSConfig.region][detectorId] = {};
        const params = {
            DetectorId: detectorId,
            FindingIds: findingIds
        };

        helpers.makeCustomCollectorCall(guardduty, 'getFindings', params, retries, null, null, null, function(err, data) {
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