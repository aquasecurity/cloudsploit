const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Load Balancer Has Public IP',
    category: 'Load Balancer',
    domain: 'Availability',
    description: 'Ensures that Azure Load Balancers is Public IP address associated.',
    more_info: 'A public IP associated with a load balancer serves as an Internet-facing frontend IP configuration.The frontend is used to access resources in the backend pool. The frontend IP can be used for members of the backend pool to egress to the Internet.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/configure-public-ip-load-balancer#change-or-remove-public-ip-address',
    recommended_action: 'Modify load balancers and add Public IP address.',
    apis: ['loadBalancers:listAll'],
    realtime_triggers: ['microsoftnetwork:loadbalancers:write', 'microsoftnetwork:loadbalancers:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.loadBalancers, function(location, rcb) {

            const loadBalancers = helpers.addSource(cache, source,
                ['loadBalancers', 'listAll', location]);

            if (!loadBalancers) return rcb();

            if (loadBalancers.err || !loadBalancers.data) {
                helpers.addResult(results, 3,
                    'Unable to query Load Balancers: ' + helpers.addError(loadBalancers), location);
                return rcb();
            }

            if (!loadBalancers.data.length) {
                helpers.addResult(results, 0, 'No existing Load Balancers found', location);
                return rcb();
            }

            for (let lb of loadBalancers.data) {
                if (!lb.id) continue;

                if (lb.frontendIPConfigurations && lb.frontendIPConfigurations.length && 
                    lb.frontendIPConfigurations.some(ipconfig => 
                        ipconfig.properties && ipconfig.properties.publicIPAddress)) {
                    helpers.addResult(results, 0, 'Load Balancer has public IP associated', location, lb.id);
                } else {
                    helpers.addResult(results, 2, 'Load Balancer does not have public IP associated', location, lb.id);
                } 
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
