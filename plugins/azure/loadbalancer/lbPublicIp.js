const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Load Balancer Public IP',
    category: 'Load Balancer',
    domain: 'Availability',
    description: 'Ensures that Azure Load Balancers have public IPs associated.',
    severity: 'Medium',
    more_info: 'A public load balancer offers a dedicated IP for Internet-facing access to backend resources. This configuration facilitates efficient egress to the Internet for backend pool members through the assigned frontend IP. It ensures streamlined connectivity and reliable resource availability, simplifying scalability to meet varying demand levels.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/configure-public-ip-load-balancer',
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
