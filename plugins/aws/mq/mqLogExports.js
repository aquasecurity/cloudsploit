var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MQ Log Exports Enabled',
    category: 'MQ',
    description: 'Ensure that Amazon MQ brokers have the Log Exports feature enabled.',
    more_info: 'Amazon MQ has a feature of AWS CloudWatch Logs, a service of storing, accessing and monitoring your log files from different sources within your AWS account.',
    recommended_action: 'Enable Log Exports feature for MQ brokers',
    link: 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/security-logging-monitoring.html',
    apis: ['MQ:listBrokers', 'MQ:describeBroker'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.mq, function(region, rcb){        
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
                    if (describeBroker.data.Logs && (describeBroker.data.Logs.Audit || describeBroker.data.Logs.General)) {
                        helpers.addResult(results, 0, 'Broker has log exports feature enabled',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2, 'Broker does not have log exports feature enabled',
                            region, resource);
                    }
                }
            }

            rcb();  
        }, function(){
            callback(null, results, source);
        });
    }
};
