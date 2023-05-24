var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Subscription Protocol',
    category: 'SNS',
    domain: 'Application Integration',
    description: 'Ensure that Amazon SNS subscriptions are using HTTPS protocol not HTTP',
    more_info: 'Amazon Simple Notification Service (Amazon SNS) is a managed service that provides message delivery from publishers to subscribers. It is important to verify that SNS subscriptions are configured to use the HTTPS protocol. ',
    recommended_action: 'Review and update SNS subscriptions to use the appropriate protocol (HTTPS)',
    link: 'https://docs.aws.amazon.com/sns/latest/dg/sns-http-https-endpoint-as-subscriber.html',
    apis: ['SNS:listSubscriptions'],

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

            for (var Subscription of listSubscriptions.data) {
                if (!Subscription.SubscriptionArn || !Subscription.Protocol) continue;

                if(Subscription.Protocol.toLowerCase() != 'https'){
                    helpers.addResult(results, 2, 'SNS subscription is not using HTTPS protocol',
                    region, Subscription.SubscriptionArn);
                }else{
                    helpers.addResult(results, 0, 'SNS subscription is using HTTPS protocol',
                    region, Subscription.SubscriptionArn);
                }

            }

            rcb();
        },function(){
            callback(null, results, source);
        });
    
    }
};