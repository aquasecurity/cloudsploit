var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail Delivery Failing',
    category: 'CloudTrail',
    description: 'Ensures that Amazon CloudTrail trail log files are delivered to destination S3 bucket.',
    more_info: 'Amazon CloudTrail trail logs should be delivered to destination S3 bucket to be used for security audits.',
    recommended_action: 'Create new S3 bucket and call UpdateTrail or fix the existing objects',
    link: 'https://forums.aws.amazon.com/thread.jspa?threadID=286952',
    apis: ['CloudTrail:describeTrails', 'CloudTrail:getTrailStatus'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.cloudtrail, function(region, rcb){

            var describeTrails = helpers.addSource(cache, source,
                ['cloudtrail', 'describeTrails', region]);

            if (!describeTrails) return rcb();

            if (describeTrails.err || !describeTrails.data) {
                helpers.addResult(results, 3,
                    `Unable to query for trails: ${helpers.addError(describeTrails)}`, region);
                return rcb();
            }

            if (!describeTrails.data.length) {
                helpers.addResult(results, 0, 'No CloudTrail trails found', region);
                return rcb();
            }

            async.each(describeTrails.data, function(trail, cb){
                if (!trail.TrailARN) return cb();

                var resource = trail.TrailARN;

                var getTrailStatus = helpers.addSource(cache, source,
                    ['cloudtrail', 'getTrailStatus', region, trail.TrailARN]);

                if (!getTrailStatus ||
                    getTrailStatus.err ||
                    !getTrailStatus.data) {
                    helpers.addResult(results, 3,
                        `Unable to query CloudTrail trail status: ${helpers.addError(getTrailStatus)}`,
                        region, resource);
                    return cb();
                }

                if (getTrailStatus.data.LatestDeliveryError) {
                    helpers.addResult(results, 2,
                        'CloudTrail trail failed to deliver the log file to the destination',
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'CloudTrail trail successfully delivered the log files to the destination',
                        region, resource);
                }
    
                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};             