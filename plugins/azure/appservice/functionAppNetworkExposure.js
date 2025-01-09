var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Internet Exposure',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Info',
    description: 'Ensures that Azure function apps are not exposed to the internet.',
    more_info: 'Azure Functions exposed to the internet are at higher risk of unauthorized access and exploitation. Securing access through proper configuration of authorization levels, IP restrictions, private endpoints, or service-specific security settings is critical to minimize vulnerabilities.',
    recommended_action: 'Restrict Azure Function exposure by implementing secure access controls, such as authorization levels, IP restrictions, private endpoints, or integrating with VNETs.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-functions/functions-networking-options',
    apis: ['webApps:list', 'applicationGateways:list', 'loadBalancers:list', 'classicFrontDoors:list', 'afdWafPolicies:listAll'],
    realtime_triggers: ['microsoftweb:sites:write','microsoftweb:sites:delete', 'microsoftnetwork:applicationgateways:write', 'microsoftnetwork:applicationgateways:delete', 'microsoftnetwork:loadbalancers:write', 'microsoftnetwork:loadbalancers:delete',
        'microsoftnetwork:frontdoors:write', 'microsoftnetwork:frontdoors:delete', 'microsoftnetwork:frontdoorwebapplicationfirewallpolicies:write', 'microsoftnetwork:frontdoorwebapplicationfirewallpolicies:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(cache, source,
                ['webApps', 'list', location]);

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Function Apps: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (webApps.data && webApps.data.length) {
                webApps.data = webApps.data.filter(app => app.id && app.kind && app.kind.toLowerCase().includes('functionapp'));
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing Function Apps found', location);
                return rcb();
            }

            const appGateways = helpers.addSource(cache, source,
                ['applicationGateways', 'list', location]);

            const loadBalancers = helpers.addSource(cache, source,
                ['loadBalancers', 'list', location]);


            const frontDoors = helpers.addSource(cache, source,
                ['classicFrontDoors', 'list', 'global']);


            const wafPolicies = helpers.addSource(cache, source,
                ['afdWafPolicies', 'listAll', 'global']);


            for (let functionApp of webApps.data) {
                let internetExposed = '';
                if (functionApp.publicNetworkAccess && functionApp.publicNetworkAccess === 'Enabled') {
                    internetExposed = 'public network access';
                } else {
                    let attachedResources = {
                        appGateways: [],
                        lbNames: [],
                        frontDoors: []
                    };

                    // list attached app gateways
                    if (appGateways && !appGateways.err && appGateways.data && appGateways.data.length) {
                        attachedResources.appGateways = appGateways.data.filter(ag =>
                            ag.backendAddressPools && ag.backendAddressPools.some(pool =>
                                pool.backendAddresses && pool.backendAddresses.some(addr =>
                                    addr.fqdn === functionApp.properties.defaultHostName)));
                    }

                    //list attached load balancers
                    if (loadBalancers && !loadBalancers.err && loadBalancers.data && loadBalancers.data.length) {
                        attachedResources.lbNames = loadBalancers.data.filter(lb =>
                            lb.backendAddressPools && lb.backendAddressPools.some(pool =>
                                pool.properties.backendIPConfigurations &&
                                pool.properties.backendIPConfigurations.some(config =>
                                    config.id.toLowerCase().includes(functionApp.id.toLowerCase()))));

                        attachedResources.lbNames = attachedResources.lbNames.map(lb => lb.name);
                    }

                    // list attached front doors
                    if (frontDoors && !frontDoors.err && frontDoors.data && frontDoors.data.length) {
                        frontDoors.data.forEach(fd => {
                            const isFunctionAppBackend = fd.backendPools && fd.backendPools.some(pool =>
                                pool.backends && pool.backends.some(backend =>
                                    backend.address === functionApp.properties.defaultHostName));

                            if (isFunctionAppBackend) {
                                fd.associatedWafPolicies = [];

                                if (fd.frontendEndpoints && wafPolicies && !wafPolicies.err && wafPolicies.data && wafPolicies.data.length) {
                                    fd.frontendEndpoints.forEach(endpoint => {
                                        if (endpoint.webApplicationFirewallPolicyLink) {
                                            const policyId = endpoint.webApplicationFirewallPolicyLink.id.toLowerCase();
                                            const matchingPolicy = wafPolicies.data.find(policy =>
                                                policy.id && policy.id.toLowerCase() === policyId);
                                            if (matchingPolicy) {
                                                fd.associatedWafPolicies.push(matchingPolicy);
                                            }
                                        }
                                    });
                                }

                                attachedResources.frontDoors.push(fd);
                            }
                        });
                    }

                    internetExposed = helpers.checkNetworkExposure(cache, source, [], [], location, results, attachedResources, functionApp);
                }

                if (internetExposed && internetExposed.length) {
                    helpers.addResult(results, 2, `Function App is exposed to the internet through ${internetExposed}`, location, functionApp.id);
                } else {
                    helpers.addResult(results, 0, 'Function App is not exposed to the internet', location, functionApp.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
