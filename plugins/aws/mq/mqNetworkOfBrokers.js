var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MQ Broker Network Topology',
    category: 'MQ',
    domain: 'Application Integration',
    description: 'Ensure that your production AWS MQ brokers are running within a mesh network of single-instance or active/standby brokers.',
    more_info: 'A network of brokers is a highly available network that connects multiple message brokers across AWS Availability Zones and regions. This network topology improves MQ brokers availability and scalability, and represents an ideal network configuration for mission-critical applications where downtime is highly impactful.',
    recommended_action: 'Configure MQ brokers to operate within a mesh network of single-instance or active/standby brokers.',
    link: 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/network-of-brokers.html',
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
                if (broker.NetworkConfiguration && broker.NetworkConfiguration.BrokerNetworkType === 'FULL_MESH') {
                    helpers.addResult(results, 0, 'Broker is part of a full mesh network',
                        region, resource);
                } else {
                    helpers.addResult(results, 2, 'Broker is not part of a full mesh network',
                        region, resource);
                }
            }
            rcb();  
        }, function(){
            callback(null, results, source);
        });
    }
};
