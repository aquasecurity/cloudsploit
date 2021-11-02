var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MQ Auto Minor Version Upgrade',
    category: 'MQ',
    domain: 'Application Integration',
    description: 'Ensure that Amazon MQ brokers have the Auto Minor Version Upgrade feature enabled.',
    more_info: 'As AWS MQ deprecates minor engine version periodically and provides new versions for upgrade, it is highly recommended that Auto Minor Version Upgrade feature is enabled to apply latest upgrades.',
    recommended_action: 'Enabled Auto Minor Version Upgrade feature for MQ brokers',
    link: 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker.html',
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
                        `Unable to get brokers description: ${helpers.addError(describeBroker)}`,
                        region, resource);
                } else {
                    if (describeBroker.data.AutoMinorVersionUpgrade) {
                        helpers.addResult(results, 0, 'Broker has auto minor version upgrade enabled',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2, 'Broker does not have auto minor version upgrade enabled',
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
