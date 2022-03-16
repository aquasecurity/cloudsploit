var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail Management Events',
    category: 'CloudTrail',
    domain: 'Compliance',
    description: 'Ensures that AWS CloudTrail trails are configured to log management events.',
    more_info: 'AWS CloudTrail trails should be configured to log management events to record management operations that are performed on resources in your AWS account.',
    recommended_action: 'Update CloudTrail service to enable management events logging',
    link: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html',
    apis: ['CloudTrail:describeTrails', 'SNS:listTopics', 'SNS:getTopicAttributes'],

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
                helpers.addResult(results, 0, 'no trail found', region);
                return rcb();
            }

            var listTopics = helpers.addSource(cache, source,
                ['sns', 'listTopics', region]);

            if (!listTopics) return rcb();

            if (listTopics.err || !listTopics.data) {
                helpers.addResult(results, 3,
                    `Unable to list topics: ${helpers.addError(listTopics)}`, region);
                return rcb();
            }

            for (let trail of describeTrails.data) {
                if (!trail.TrailARN) continue;

                var resource = trail.TrailARN;
                var getTopicAttributes = helpers.addSource(cache, source,
                    ['sns', 'getTopicAttributes', region, trail.SnsTopicARN]);

                if (getTopicAttributes && getTopicAttributes.err && getTopicAttributes.err.code &&
                    getTopicAttributes.err.code == 'NotFound') {
                    helpers.addResult(results, 2,
                        'SNS notifications are deleted for the selected CloudTrail trail after manufacture of trail', region, resource);
                    continue;
                } 

                if (getTopicAttributes.err) {
                    helpers.addResult(results, 3,
                        'unable to query for SNS notifications'+ helpers.addError(getTopicAttributes), 
                        region, resource);
                    continue;
                } 

                if (!getTopicAttributes || !getTopicAttributes.data) {
                    helpers.addResult(results, 2,
                        'SNS notifications are not enabled for trail', 
                        region, resource);
                }  else {
                    helpers.addResult(results, 0,
                        'SNS notifications are enabled for trail',
                        region, resource);
                }
            }

            rcb();
        }, function() {
            return callback(null, results, source);
        });
    },
};
