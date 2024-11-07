var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Subscription HTTPS Only',
    category: 'SNS',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Amazon SNS subscriptions are configured to use HTTPS protocol',
    more_info: 'Amazon Simple Notification Service (Amazon SNS) is a managed service that provides message delivery from publishers to subscribers. It is important to verify that SNS subscriptions are configured to use the HTTPS protocol.',
    recommended_action: 'Create a new SNS subscription using HTTPS protocol.',
    link: 'https://docs.aws.amazon.com/sns/latest/dg/sns-http-https-endpoint-as-subscriber.html',
    apis: ['SNS:listSubscriptions'],
    realtime_triggers: ['sns:Subscribe', 'sns:Unsubscribe'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.sns, function(region, rcb) {
            var listSubscriptions = helpers.addSource(cache, source,
                ['sns', 'listSubscriptions', region]);

            if (!listSubscriptions) return rcb();

            if (listSubscriptions.err) {
                helpers.addResult(results, 3,
                    'Unable to query for SNS subscriptions: ' +
                    helpers.addError(listSubscriptions), region);
                return rcb();
            }

            if (!listSubscriptions.data || !listSubscriptions.data.length) {
                helpers.addResult(results, 0, 'No SNS subscriptions found', region);
                return rcb();
            }

            for (var subscription of listSubscriptions.data) {
                if (!subscription.SubscriptionArn || !subscription.Protocol) continue;

                if (subscription.Protocol.toLowerCase() != 'https'){
                    helpers.addResult(results, 2, 'SNS subscription is not using HTTPS protocol',
                        region, subscription.SubscriptionArn);
                } else {
                    helpers.addResult(results, 0, 'SNS subscription is using HTTPS protocol',
                        region, subscription.SubscriptionArn);
                }
            }

            rcb();
        },function(){
            callback(null, results, source);
        });

    }
};


