var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail Notifications Enabled',
    category: 'CloudTrail',
    domain: 'Compliance',
    severity: 'MEDIUM',
    description: 'Ensure that Amazon CloudTrail trails are using active Simple Notification Service (SNS) topics to deliver notifications.',
    more_info: 'CloudTrail trails should reference active SNS topics to notify for log files delivery to S3 buckets. Otherwise, you will lose the ability to take immediate actions based on log information.',
    recommended_action: 'Make sure that CloudTrail trails are using active SNS topics and that SNS topics have not been deleted after trail creation.',
    link: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html',
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
                    `Unable to query for CloudTrail trails: ${helpers.addError(describeTrails)}`, region);
                return rcb();
            }

            if (!describeTrails.data.length) {
                helpers.addResult(results, 0, 'No CloudTrail trails found', region);
                return rcb();
            }

            var listTopics = helpers.addSource(cache, source,
                ['sns', 'listTopics', region]);

            if (!listTopics) return rcb();

            if (listTopics.err || !listTopics.data) {
                helpers.addResult(results, 3,
                    `Unable to query for SNS topics: ${helpers.addError(listTopics)}`, region);
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
                        'CloudTrail trail SNS topic not found', region, resource);
                    continue;
                } 

                if (!getTopicAttributes || getTopicAttributes.err ||
                    !getTopicAttributes.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for SNS topic: ${helpers.addError(describeTrails)}`, 
                        region, resource);
                }  else {
                    helpers.addResult(results, 0,
                        'CloudTrail trail is using active SNS topic',
                        region, resource);
                }
            }

            rcb();
        }, function() {
            return callback(null, results, source);
        });
    },
};
