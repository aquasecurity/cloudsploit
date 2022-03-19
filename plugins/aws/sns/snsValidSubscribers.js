var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Valid Subscribers',
    category: 'SNS',
    domain: 'Application Integration',
    description: 'Ensure that Amazon SNS subscriptions are valid and there are no unwanted subscribers.',
    more_info: 'Amazon Simple Notification Service (Amazon SNS) is a managed service that provides message delivery from publishers to subscribers. So check for appropriate subsribers in order to improve access security to your SNS topics. ',
    recommended_action: 'Check for unwanted SNS subscriptions periodically',
    link: 'https://docs.aws.amazon.com/sns/latest/dg/sns-create-subscribe-endpoint-to-topic.html',
    apis: ['SNS:listSubscriptions'],
    settings: {
        sns_unwanted_subscribers: {
            name: 'SNS Unwanted Subscribers',
            description: 'Comma-separated list of subscription endpoint i.e. xyz@aquasec.com',
            regex: '^.*$',
            default: '',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            sns_unwanted_subscribers: settings.sns_unwanted_subscribers || this.settings.sns_unwanted_subscribers.default
        };

        config.sns_unwanted_subscribers = config.sns_unwanted_subscribers.replace(/\s+/g, '');

        if (!config.sns_unwanted_subscribers.length) return callback(null, results, source);

        config.sns_unwanted_subscribers = config.sns_unwanted_subscribers.toLowerCase();

        async.each(regions.sns, function(region, rcb){
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
                helpers.addResult(
                    results, 0, 'No SNS subscriptions Found', region);
                return rcb();
            }

            for (let subscriber of listSubscriptions.data) {
                if (!subscriber.SubscriptionArn) continue;

                let resource = subscriber.SubscriptionArn;

                if (subscriber.Endpoint && config.sns_unwanted_subscribers.includes(subscriber.Endpoint.toLowerCase())){
                    helpers.addResult(results, 2,
                        'SNS subscription is an unwanted subscription', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'SNS subscription is a wanted subscription', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
