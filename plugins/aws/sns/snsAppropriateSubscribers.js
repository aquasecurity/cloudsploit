var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Appropriate Subscribers',
    category: 'SNS',
    domain: 'Application Integration',
    description: 'Ensure that Amazon SNS subscriptions are valid and there are no unwanted subscribers.',
    more_info: 'Amazon Simple Notification Service (Amazon SNS) is a managed service that provides message delivery from publishers to subscribers. So check for appropriate subsribers in order to improve access security to your SNS topics. ',
    recommended_action: 'Check for unwanted SNS subscriptions periodically',
    link: 'https://docs.aws.amazon.com/sns/latest/dg/sns-create-subscribe-endpoint-to-topic.html',
    apis: ['SNS:listSubscriptions'],
    settings: {
        sns_unwanted_subscribers_endpoint: {
            name: 'SNS Unwanted Subscribers Endpoint',
            description: 'endpoint for SNS subscrptions that are unwanted',
            regex: '^.*$',
            default: '',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            sns_unwanted_subscribers_endpoint: settings.sns_unwanted_subscribers_endpoint || this.settings.sns_unwanted_subscribers_endpoint.default
        };

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

            for (let i in listSubscriptions.data) {
                let subscriber = listSubscriptions.data[i];
                let resource = subscriber.SubscriptionArn;

                if (subscriber.Endpoint == config.sns_unwanted_subscribers_endpoint){
                    helpers.addResult(results, 2,
                        'SNS subscriber is unwanted for topic', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'SNS subscriber is appropriate for topic', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
