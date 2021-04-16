var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail Delivery Failing',
    category: 'CloudTrail',
    description: 'Ensures that Amazon CloudTrail trail log files are delivered to destination S3 bucket.',
    more_info: 'Amazon CloudTrail trail logs should be delivered to destination S3 bucket to be used for security audits.',
    recommended_action: 'Modify CloudTrail trail configurations so that logs are being delivered',
    link: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html',
    apis: ['CloudTrail:describeTrails', 'CloudTrail:getTrailStatus'],
    settings: {
        trails_to_check: {
            name: 'CloudTrail Trails to Check',
            description: 'Comma separated string of CloudTrail trail names. If provided, only check provided trails and pass all other without checking',
            regex: '^[0-9A-Za-z._-]{3,128}$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            trails_to_check: settings.trails_to_check || this.settings.trails_to_check.default
        };

        var checkProvidedOnly = (config.trails_to_check.length) ? true : false;

        config.trails_to_check = config.trails_to_check.split(',');

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
                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
                return rcb();
            }

            async.each(describeTrails.data, function(trail, cb){
                if (!trail.TrailARN || (trail.S3BucketName && trail.S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET)) return cb();

                var resource = trail.TrailARN;

                if (checkProvidedOnly && trail.Name && !config.trails_to_check.includes(trail.Name)) {
                    helpers.addResult(results, 0,
                        `CloudTrail trail "${trail.Name}" is set to pass without checking logs delivery status`,
                        region, resource);
                    return cb();
                }

                var getTrailStatus = helpers.addSource(cache, source,
                    ['cloudtrail', 'getTrailStatus', region, trail.TrailARN]);

                if (!getTrailStatus || getTrailStatus.err || !getTrailStatus.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for CloudTrail trail status: ${helpers.addError(getTrailStatus)}`,
                        region, resource);
                    return cb();
                }

                if (getTrailStatus.data.LatestDeliveryError) {
                    helpers.addResult(results, 2,
                        `Logs for CloudTrail trail "${trail.Name}" are not being delivered`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        `Logs for CloudTrail trail "${trail.Name}" are being delivered`,
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