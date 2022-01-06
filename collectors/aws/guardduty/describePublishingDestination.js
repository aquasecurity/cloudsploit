var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var guardduty = new AWS.GuardDuty(AWSConfig);

    if (!collection.guardduty ||
        !collection.guardduty.listDetectors ||
        !collection.guardduty.listDetectors[AWSConfig.region] ||
        !collection.guardduty.listDetectors[AWSConfig.region].data) return callback();

    async.eachLimit(collection.guardduty.listDetectors[AWSConfig.region].data, 5, function(detectorId, cb){
       
        if (!detectorId || !collection.guardduty ||
            !collection.guardduty.listPublishingDestinations ||
            !collection.guardduty.listPublishingDestinations[AWSConfig.region] ||
            !collection.guardduty.listPublishingDestinations[AWSConfig.region][detectorId] ||
            !collection.guardduty.listPublishingDestinations[AWSConfig.region][detectorId].data ||
            !collection.guardduty.listPublishingDestinations[AWSConfig.region][detectorId].data.Destinations ||
            !collection.guardduty.listPublishingDestinations[AWSConfig.region][detectorId].data.Destinations.length) {
            return cb();
        }

        async.eachLimit(collection.guardduty.listPublishingDestinations[AWSConfig.region][detectorId].data.Destinations, 3, function(destination, pCb){
            collection.guardduty.describePublishingDestination[AWSConfig.region][destination.DestinationId] = {};

            // Make the describe destinations call
            helpers.makeCustomCollectorCall(guardduty, 'describePublishingDestination', {DestinationId: destination.DestinationId, DetectorId: detectorId}, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.guardduty.describePublishingDestination[AWSConfig.region][destination.DestinationId].err = err;
                }

                collection.guardduty.describePublishingDestination[AWSConfig.region][destination.DestinationId].data = data;
                pCb();
            });

        }, function() {
            cb();
        });
    }, function(){
        callback();
    });
};