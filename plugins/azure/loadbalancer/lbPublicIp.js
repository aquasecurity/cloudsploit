const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Public Load Balancer',
    category: 'Load Balancer',
    domain: 'Availability',
    description: 'Ensures that Azure Load Balancers are configured as public.',
    severity: 'Medium',
    more_info: 'To meet your organization\'s security compliance, ensure that load balancers are public to facilitate efficient egress to the Internet for backend pool members through the assigned frontend IP, ensuring streamlined connectivity and reliable resource availability.',
    link: 'https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-overview',
    recommended_action: 'Create the Load Balancer with Ip associations as per your organization\'s requirements.',
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
                    helpers.addResult(results, 0, 'Load Balancer is configured as public', location, lb.id);
                } else {
                    helpers.addResult(results, 2, 'Load Balancer is not configured as public', location, lb.id);
                } 
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
