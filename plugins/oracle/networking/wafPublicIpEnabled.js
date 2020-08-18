var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'WAF Public IP Enabled',
    category: 'Networking',
    description: 'Ensures all public IPs have WAF enabled',
    more_info: 'Every Public IP address should have a firewall enabled to control access to the endpoints. Enabling a Web Application Firewall follows security best practices and helps prevent malicious attempts to access the network.',
    recommended_action: 'Ensure all Public IPs have WAF enabled',
    link: 'https://docs.cloud.oracle.com/iaas/Content/WAF/Concepts/gettingstarted.htm',
    apis: ['publicIp:list', 'waasPolicy:list', 'waasPolicy:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);
        async.each(regions.publicIp, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var publicIps = helpers.addSource(cache, source,
                    ['publicIp', 'list', region]);

                if (!publicIps) return rcb();

                if (publicIps.err || !publicIps.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for public IPs: ' + helpers.addError(publicIps), region);
                    return rcb();
                }

                if (!publicIps.data.length) {
                    helpers.addResult(results, 0, 'No public IPs present', region);
                    return rcb();
                }

                var waasPolicies = helpers.addSource(cache, source,
                    ['waasPolicy', 'get', region]);

                if (!waasPolicies) return rcb();

                if (waasPolicies.err || !waasPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for waas policies: ' + helpers.addError(waasPolicies), region);
                    return rcb();
                }
                
                var waasIps = [];
                waasPolicies.data.forEach(waasPolicy => {
                    if (waasPolicy.origins &&
                        waasPolicy.origins.length) {
                        for (var x in waasPolicy.origins) {
                            var origin = waasPolicy.origins[x];
                            if (origin.uri) {
                                waasIps.push(origin.uri);
                            }
                        }
                    }
                });

                publicIps.data.forEach(publicIp => {
                    if (waasIps.indexOf(publicIp.ipAddress) > -1) {
                        helpers.addResult(results, 0, 'The public IP has WAF enabled', region, publicIp.id);
                    } else {
                        helpers.addResult(results, 2, 'The public IP has WAF disabled', region, publicIp.id);
                    }
                });
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};