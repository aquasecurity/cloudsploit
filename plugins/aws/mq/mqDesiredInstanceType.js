var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MQ Desired Broker Instance Type',
    category: 'MQ',
    description: 'Ensure that the Amazon MQ broker instances are created with desired instance types.',
    more_info: 'Set limits for the type of Amazon MQ broker instances created in your AWS account to address internal compliance ' +
        'requirements and prevent unexpected charges on your AWS bill.',
    recommended_action: 'Create MQ broker with desired instance types',
    link: 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-broker-architecture.html',
    apis: ['MQ:listBrokers'],
    settings: {
        mq_desired_instance_type: {
            name: 'MQ Desired Broker Instance Types',
            description: 'Comma-separated list of desired MQ broker instance types',
            regex: '^.*$',
            default:''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            mq_desired_instance_type: settings.mq_desired_instance_type || this.settings.mq_desired_instance_type.default
        };
        
        if (!config.mq_desired_instance_type.length) return callback(null, results, source);

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

            for (var broker of listBrokers.data) {
                if (!broker.BrokerArn) continue;

                if (broker.HostInstanceType && broker.HostInstanceType.length &&
                    config.mq_desired_instance_type.includes(broker.HostInstanceType)) {
                    helpers.addResult(results, 0,
                        `Broker has desired instance type: ${broker.HostInstanceType}`,
                        region, broker.BrokerArn);
                } else {
                    helpers.addResult(results, 2,
                        `Broker does not have desired instance type: ${broker.HostInstanceType}`,
                        region, broker.BrokerArn);
                }
            }

            rcb();  
        }, function(){
            callback(null, results, source);
        });
    }
};
