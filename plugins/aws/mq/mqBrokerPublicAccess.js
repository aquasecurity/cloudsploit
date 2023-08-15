var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MQ Broker Public Accessibility',
    category: 'MQ',
    domain: 'Application Integration',
    description: 'Ensure that Amazon MQ brokers are not publicly accessible from the Internet.',
    recommended_action: 'Review and update the security group settings to restrict public access to Amazon MQ brokers.',
    link: 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-security-groups.html',
    apis: ['MQ:listBrokers', 'MQ:describeBroker', 'EC2:describeSecurityGroups'],
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

            async.each(listBrokers.data, function(broker, bcb) {
                if (!broker.BrokerArn) return bcb();

                let resource = broker.BrokerArn;
                let brokerId = broker.BrokerId;

                var describeBroker = helpers.addSource(cache, source,
                    ['mq', 'describeBroker', region, brokerId]);

                if (!describeBroker || describeBroker.err || !describeBroker.data) {
                    helpers.addResult(results, 3,
                        `Unable to describe MQ broker: ${helpers.addError(describeBroker)}`,
                        region, resource);
                    return bcb();
                }
                if (describeBroker.data.PubliclyAccessible) {
                    helpers.addResult(results, 2,
                        'MQ Broker is publicly accessible from the Internet',
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'MQ Broker is not publicly accessible from the Internet',
                        region, resource);
                }

                bcb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};