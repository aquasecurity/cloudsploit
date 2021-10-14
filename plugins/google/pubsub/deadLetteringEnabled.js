var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Dead Lettering Enabled',
    category: 'Pub/Sub',
    domain: 'Application Integration',
    description: 'Ensure that each Google Pub/Sub subscription is configured to use dead-letter topic.',
    more_info: 'Enabling dead lettering will handle message failures by forwarding undelivered messages to a dead-letter topic that stores the message for later access.',
    link: 'https://cloud.google.com/pubsub/docs/dead-letter-topics',
    recommended_action: 'Ensure that dead letter topics are configured for all your Google Cloud Pub/Sub subscriptions.',
    apis: ['subscriptions:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.subscriptions, function(region, rcb){
            var subscriptions = helpers.addSource(cache, source,
                ['subscriptions', 'list', region]);
        
            if (!subscriptions) return rcb();
        
            if (subscriptions.err || !subscriptions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Pub/Sub subscriptions: ' + helpers.addError(subscriptions), region, null, null, subscriptions.err);
                return rcb();
            }
        
            if (!subscriptions.data.length) {
                helpers.addResult(results, 0, 'No Pub/Sub subscriptions found', region);
                return rcb();
            }

            subscriptions.data.forEach(subscription => {
                if (!subscription.name) return;

                if (subscription.deadLetterPolicy && subscription.deadLetterPolicy.deadLetterTopic) {
                    helpers.addResult(results, 0,
                        'Pub/Sub subscription has dead lettering enabled', region, subscription.name);
                } else {
                    helpers.addResult(results, 2,
                        'Pub/Sub subscription does not have dead lettering enabled', region, subscription.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });        
    }
};
