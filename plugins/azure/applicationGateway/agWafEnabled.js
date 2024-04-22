const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Gateway WAF Enabled',
    category: 'Application Gateway',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensure that Web Application FireWall (WAF) is enabled for Application Gateways.',
    more_info: 'Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities.',
    recommended_action: 'Modify application gateway and enable WAF.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview',
    apis: ['applicationGateway:listAll'],
    realtime_triggers: ['microsoftnetwork:applicationgateways:write','microsoftnetwork:applicationgateways:delete','microsoftnetwork:applicationgatewaywebapplicationfirewallpolicies:write','microsoftnetwork:applicationgatewaywebapplicationfirewallpolicies:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.applicationGateway, (location, rcb) => {
            var appGateways = helpers.addSource(cache, source, 
                ['applicationGateway', 'listAll', location]);

            if (!appGateways) return rcb();

            if (appGateways.err || !appGateways.data) {
                helpers.addResult(results, 3, 'Unable to query for Application Gateway: ' + helpers.addError(appGateways), location);
                return rcb();
            }

            if (!appGateways.data.length) {
                helpers.addResult(results, 0, 'No existing Application Gateway found', location);
                return rcb();
            } 
            
            for (let appGateway of appGateways.data) {
                if (!appGateway.id) continue;

                if (appGateway.sku.tier != 'WAF_v2'){
                    helpers.addResult(results, 2, 'Prevention mode is not supported for WAF Standard v2 tier', location, appGateway.id);
                    continue;
                }

                if (appGateway.webApplicationFirewallConfiguration && appGateway.webApplicationFirewallConfiguration.enabled 
                    && appGateway.webApplicationFirewallConfiguration.enabled === true) {
                    helpers.addResult(results, 0, 'Web Application Firewall is enabled for Application Gateway', location, appGateway.id);
                } else {
                    helpers.addResult(results, 2, 'Web Application Firewall is not enabled for Application Gateway', location, appGateway.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
