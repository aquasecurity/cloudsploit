var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail Data Events',
    category: 'CloudTrail',
    description: 'Ensure Data events are included into Amazon CloudTrail trails configuration.',
    more_info: 'AWS CloudTrail trails should be configured to enable Data Events in order to log S3 object-level API operations.',
    recommended_action: 'Update CloudTrail to enable data events.',
    link: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html',
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
                helpers.addResult(results, 0, 'No CloudTrail trails found', region);
                return rcb();
            }

            async.each(describeTrails.data, function(trail, cb){
                if (!trail.TrailARN) return cb();

                var resource = trail.TrailARN;
                
                var getEventSelectors = helpers.addSource(cache, source,
                    ['cloudtrail', 'getEventSelectors', region, trail.TrailARN]);

                if (!getEventSelectors ||
                    getEventSelectors.err ||
                    !getEventSelectors.data ||
                    !getEventSelectors.data.EventSelectors) {
                    helpers.addResult(results, 3,
                        `Unable to query event selectors: ${helpers.addError(getEventSelectors)}`, region, resource);
                    return cb();
                }

                var dataResourceFound = false;
                for (var e in getEventSelectors.data.EventSelectors){
                    var eventSelector = getEventSelectors.data.EventSelectors[e];

                    if (eventSelector.DataResources && eventSelector.DataResources.length) {
                        dataResourceFound = true;
                        break;
                    }
                }

                if (dataResourceFound) {
                    helpers.addResult(results, 0,
                        `CloudTrail trail "${trail.Name}" has Data Events configured`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `CloudTrail trail "${trail.Name}" does not have Data Events configured`, region, resource);
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