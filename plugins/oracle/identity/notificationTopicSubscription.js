var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Notification Topic With Active Subscription',
    category: 'Identity',
    domain: 'Logging and Monitoring',
    description: 'Ensure that there is at least one notification topic and subscription to receive monitoring alerts.',
    more_info: 'Creating and subscribing to one or more notification topics allows administrators to be notified of any changes in the Oracle Cloud Infrastructure.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Notification/Tasks/managingtopicsandsubscriptions.htm',
    recommended_action: 'Create at least one notification topic with an active subscription.',
    apis: ['topics:list','subscriptions:list'],


    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.subscriptions, function(region, rcb) {
            if (helpers.checkRegionSubscription(cache, source, results, region)) {
                var topics = helpers.addSource(cache, source,
                    ['topics', 'list', region]);

                if (!topics) return rcb();

                if (topics.err || !topics.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for topics: ' + helpers.addError(topics), region);
                    return rcb();
                }
                if (!topics.data.length) {
                    helpers.addResult(results, 2, 'No topics found', region);
                    return rcb();
                } 

                const activeTopic = topics.data.find(topic =>
                    topic.lifecycleState && topic.lifecycleState === 'ACTIVE'
                );

                if (!activeTopic) {
                    helpers.addResult(results, 2,
                        'No active topics found in the region', region);
                    return rcb();
                }

                var subscriptions = helpers.addSource(cache, source,
                    ['subscriptions', 'list', region]);


                if (!subscriptions || subscriptions.err || !subscriptions.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for subscriptions: ' + helpers.addError(subscriptions), region);
                    return rcb();
                }
                if (!subscriptions.data.length) {
                    helpers.addResult(results, 2, 'No subscriptions found in the region', region);
                    return rcb();
                }

                const activeSubscription = subscriptions.data.find(subscription =>
                    subscription.lifecycleState && subscription.lifecycleState === 'ACTIVE'
                );

                if (activeSubscription) {
                    helpers.addResult(results, 0,
                        'There is at least one notification topic with an active subscription', region);
                } else {
                    helpers.addResult(results, 2,
                        'No notification topics with active subscriptions found', region);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
