var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MQ Desired Broker Instance Type',
    category: 'MQ',
    description: 'Ensure that the Amazon MQ broker instances provisioned in your AWS account have the desired instance type established within your organization based on the workload deployed.',
    more_info: 'Setting limits for the type of Amazon MQ broker instances created in your AWS account will help you address internal compliance requirements and prevent unexpected charges on your AWS bill.',
    recommended_action: 'Enable Desired Instance type for MQ brokers',
    link: 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-broker-architecture.html',
    apis: ['MQ:listBrokers'],
    settings: {
        mq_desired_instance_type: {
            name: 'MQ Desired Broker Instance Type',
            description: 'MQ brokers should be using the desired instance type',
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
           
            for (var f in listBrokers.data) {
                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
                var broker = listBrokers.data[f];

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
