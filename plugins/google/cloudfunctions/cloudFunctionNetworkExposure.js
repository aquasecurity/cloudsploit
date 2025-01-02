var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Network Exposure',
    category: 'Cloud Functions',
    domain: 'Serverless',
    severity: 'Info',
    description: 'Ensures Cloud Functions are not publicly exposed to all inbound traffic.',
    more_info: 'Cloud Functions should be properly secured using ingress settings and load balancer configurations to control which sources can invoke the function.',
    link: 'https://cloud.google.com/functions/docs/networking/network-settings',
    recommended_action: 'Modify the Cloud Function to restrict ingress settings and ensure load balancer and api gateway configurations are properly secured.',
    apis: ['functions:list', 'urlMaps:list', 'targetHttpProxies:list', 'targetHttpsProxies:list',
        'forwardingRules:list', 'backendServices:list', 'apiGateways:list', 'api:list', 'apiConfigs:list', 'apiGateways:getIamPolicy'],
    realtime_triggers: ['functions.CloudFunctionsService.UpdateFunction', 'functions.CloudFunctionsService.CreateFunction', 'functions.CloudFunctionsService.DeleteFunction',
        'compute.backendServices.insert', 'compute.backendServices.delete', 'compute.backendServices.patch', 'compute.instanceGroups.removeInstances', 'compute.urlMaps.insert', 'compute.urlMaps.delete', 'compute.urlMaps.update', 'compute.urlMaps.patch',
        'compute.targetHttpProxies.insert', 'compute.targetHttpProxies.delete', 'compute.targetHttpProxies.patch', 'compute.targetHttpsProxies.insert', 'compute.targetHttpsProxies.delete', 'compute.targetHttpsProxies.patch',
        'compute.forwardingRules.insert', 'compute.forwardingRules.delete', 'compute.forwardingRules.patch', 'apigateway.gateways.create', 'apigateway.gateways.update', 'apigateway.gateways.delete'
    ],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        let apiGateways = [], apis = [], apiConfigs = [];
        for (let region of regions.apiGateways) {
            var gateways = helpers.addSource(cache, source,
                ['apiGateways', 'list', region]);

            if (gateways && !gateways.err && gateways.data && gateways.data.length) {
                apiGateways = apiGateways.concat(gateways.data);
            }


            var apiList = helpers.addSource(cache, source,
                ['api', 'list', region]);

            if (apiList && !apiList.err && apiList.data && apiList.data.length) {
                apis = apis.concat(apiList.data);
            }

            var configs = helpers.addSource(cache, source,
                ['apiConfigs', 'list', region]);

            if (configs && !configs.err && configs.data && configs.data.length) {
                apiConfigs = apiConfigs.concat(configs.data);
            }
        }

        async.each(regions.functions, (region, rcb) => {
            var functions = helpers.addSource(cache, source,
                ['functions', 'list', region]);

            if (!functions) return rcb();

            if (functions.err || !functions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Google Cloud Functions: ' + helpers.addError(functions), region, null, null, functions.err);
                return rcb();
            }

            if (!functions.data.length) {
                helpers.addResult(results, 0, 'No Google Cloud functions found', region);
                return rcb();
            }

            functions.data.forEach(func => {
                if (!func.name) return;
                let internetExposed = '';
                if (func.ingressSettings && func.ingressSettings.toUpperCase() == 'ALLOW_ALL') {
                    internetExposed = 'public access';
                } else if (func.ingressSettings && func.ingressSettings.toUpperCase() == 'ALLOW_INTERNAL_AND_GCLB') {
                    // only check load balancer flow if it allows traffic from LBs
                    let forwardingRules = [];
                    forwardingRules = helpers.getForwardingRules(cache, source, region, func);
                    let firewallRules = [];
                    let networks = [];
                    internetExposed = helpers.checkNetworkExposure(cache, source, networks, firewallRules, region, results, forwardingRules);

                    if (!internetExposed || !internetExposed.length) {
                        const gatewayPolicies = helpers.addSource(cache, source,
                            ['apiGateways', 'getIamPolicy', region]);

                        if (apiGateways && apiGateways.length && apiConfigs && apiConfigs.length) {
                            apiGateways.forEach(gateway => {
                                let isGatewayExposed = false;
                                if (!gateway.apiConfig || !gateway.defaultHostname) return;

                                const apiConfig = apiConfigs.find(config =>
                                    gateway.apiConfig.includes(config.name));

                                if (!apiConfig) return;

                                if (apiConfig.openapiDocuments) {
                                    const specs = apiConfig.openapiDocuments.map(doc =>
                                        typeof doc === 'string' ? JSON.parse(doc) : doc);

                                    const hasFunctionReference = specs.some(spec =>
                                        JSON.stringify(spec).includes(func.httpsTrigger.url) ||
                                        JSON.stringify(spec).includes(func.name)
                                    );

                                    if (!hasFunctionReference) return;

                                    const gatewayPolicy = gatewayPolicies.data.find(policy =>
                                        policy.parent && policy.parent.name === gateway.name);

                                    if (gatewayPolicy && gatewayPolicy.bindings) {
                                        const publicAccess = gatewayPolicy.bindings.some(binding =>
                                            binding.members.includes('allUsers') ||
                                            binding.members.includes('allAuthenticatedUsers'));
                                        if (publicAccess) {
                                            isGatewayExposed = true;
                                        }
                                    }

                                    if (!apiConfig.securityDefinitions || !Object.keys(apiConfig.securityDefinitions).length ||
                                        !apiConfig.security || !apiConfig.security.length) {
                                        isGatewayExposed = true;
                                    }


                                    if (isGatewayExposed) {
                                        internetExposed += internetExposed.length ? `, ag ${gateway.displayName}` : `ag ${gateway.displayName}`;
                                    }
                                }
                            });
                        }
                    }

                }

                if (internetExposed && internetExposed.length) {
                    helpers.addResult(results, 2, `Cloud function is exposed to the internet through ${internetExposed}`, region, func.name);
                } else {
                    helpers.addResult(results, 0, 'Cloud function is not exposed to the internet', region, func.name);
                }


            });

            rcb();
        }, function() {
            callback(null, results, source);
        });

    }
};

