var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MQ Deployment Mode',
    category: 'MQ',
    domain: 'Application Integration',
    description: 'Ensure that for high availability, your AWS MQ brokers are using the active/standby deployment mode instead of single-instance ',
    more_info: 'With the active/standby deployment mode as opposed to the single-broker mode (enabled by default), you can achieve high availability for your Amazon MQ brokers as the service provides failure proof no risk.',
    recommended_action: 'Enabled Deployment Mode feature for MQ brokers',
    link: 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/active-standby-broker-deployment.html',
    apis: ['MQ:listBrokers'],

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

                if (broker.DeploymentMode && broker.DeploymentMode.toUpperCase() === 'ACTIVE_STANDBY_MULTI_AZ') {
                    helpers.addResult(results, 0, 'Broker has active/standby deployment mode enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 2, 'Broker does not have active/standby deployment mode enabled',
                        region, resource);
                }
            }
            rcb();  
        }, function(){
            callback(null, results, source);
        });
    }
};
