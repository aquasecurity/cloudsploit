var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MQ Latest Engine Version',
    category: 'MQ',
    domain: 'Application Integration',
    severity: 'Low',
    description: 'Ensure that Amazon MQ brokers are using the latest version of Apache ActiveMQ broker engine.',
    more_info: 'Using the latest version of Apache ActiveMQ engine helps follow AWS best practices and benefits from the latest features, performance improvements, and security updates.',
    recommended_action: 'Update Amazon MQ brokers to the latest version of Apache ActiveMQ broker engine.',
    link: 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/activemq-version-management.html',
    apis: ['MQ:listBrokers', 'MQ:describeBroker'],
    realtime_triggers: ['mq:CreateBrocker','mq:UpdateBrocker', 'mq:DeleteBrocker'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        
        var latestVersion = '5.17.3';

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
                        `Unable to get broker description: ${helpers.addError(describeBroker)}`,
                        region, resource);
                } else {
                    let currentVersion = describeBroker.data.EngineVersion;
                    if (helpers.compareVersions(currentVersion,latestVersion) >= 0) {
                        helpers.addResult(results, 0, 'Broker is using the latest ActiveMQ version',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2, 'Broker is not using the latest ActiveMQ version',
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
