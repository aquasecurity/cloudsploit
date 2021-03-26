var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail Management Events',
    category: 'CloudTrail',
    description: 'Ensures that AWS CloudTrail trails are configured to log management events.',
    more_info: 'AWS CloudTrail trails should be configured to log management events to record management operations that are performed on resources in your AWS account.',
    recommended_action: 'Update CloudTrail to enable management events logging',
    link: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html',
    apis: ['CloudTrail:describeTrails', 'CloudTrail:getEventSelectors'],

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
                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
                return rcb();
            }

            async.each(describeTrails.data, function(trail, cb){
                if (!trail.TrailARN) return cb();

                var resource = trail.TrailARN;
                var getEventSelectors = helpers.addSource(cache, source,
                    ['cloudtrail', 'getEventSelectors', region, trail.TrailARN]);

                if (!getEventSelectors || getEventSelectors.err ||
                    !getEventSelectors.data || !getEventSelectors.data.EventSelectors) {
                    helpers.addResult(results, 3,
                        `Unable to query for event selectors: ${helpers.addError(getEventSelectors)}`, region, resource);
                    return cb();
                }

                var managementResourceFound = false;
                for (var eventSelector of getEventSelectors.data.EventSelectors){
                    if (eventSelector.IncludeManagementEvents) {
                        managementResourceFound = true;
                        break;
                    }
                }

                if (managementResourceFound) {
                    helpers.addResult(results, 0,
                        `CloudTrail trail "${trail.Name}" is configured to log management events`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `CloudTrail trail "${trail.Name}" is not configured to log management events`,
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