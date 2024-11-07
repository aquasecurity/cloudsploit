var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MQ Broker Public Accessibility',
    category: 'MQ',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure that Amazon MQ brokers are not publicly accessible.',
    more_info: 'Public Amazon MQ brokers can be accessed directly, outside of a Virtual Private Cloud (VPC), therefore every machine on the internet can reach your brokers through their public endpoints and this can increase the opportunity for malicious activity.',
    recommended_action: 'Review and update the security group settings to restrict public access to Amazon MQ brokers.',
    link: 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html',
    apis: ['MQ:listBrokers', 'MQ:describeBroker', 'EC2:describeSecurityGroups'],
    realtime_triggers: ['mq:CreateBrocker', 'mq:UpdateBroker', 'mq:DeleteBrocker'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.mq, function(region, rcb) {
            var listBrokers = helpers.addSource(cache, source,
                ['mq', 'listBrokers', region]);

            if (!listBrokers) return rcb();

            if (listBrokers.err || !listBrokers.data) {
                helpers.addResult(results, 3,
                    'Unable to query MQ brokers: ' + helpers.addError(listBrokers), region);
                return rcb();
            }

            if (!listBrokers.data.length) {
                helpers.addResult(results, 0, 'No MQ brokers found', region);
                return rcb();
            }

            for (let broker of listBrokers.data) {	
                if (!broker.BrokerArn) continue;

                let resource = broker.BrokerArn;

                var describeBroker = helpers.addSource(cache, source,
                    ['mq', 'describeBroker', region, broker.BrokerId]);

                if (!describeBroker || describeBroker.err || !describeBroker.data) {
                    helpers.addResult(results, 3,
                        `Unable to describe MQ broker: ${helpers.addError(describeBroker)}`,
                        region, resource);
                } else {
                    if (describeBroker.data.PubliclyAccessible) {
                        helpers.addResult(results, 2,
                            'MQ Broker is publicly accessible',
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'MQ Broker is not publicly accessible',
                            region, resource);
                    }
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};