var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECS Service Assign Public IP Disabled',
    category: 'ECS',
    domain: 'Containers',
    severity: 'High',
    description: 'Ensures that assignPublicIp is set to disabled for Amazon ECS services to restrict direct exposure of containers to the public internet.',
    more_info: 'Enabling public IP assignment could expose container application servers to unintended or unauthorized access. Services should use private networking with NAT gateways or VPC endpoints for outbound internet access.',
    link: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-networking.html',
    recommended_action: 'Modify ECS services to set assignPublicIp to disabled in the network configuration.',
    apis: ['ECS:listClusters', 'ECS:listServices', 'ECS:describeServices'],
    realtime_triggers: ['ecs:CreateService', 'ecs:UpdateService', 'ecs:DeleteService', 'ecs:CreateCluster', 'ecs:DeleteCluster', 'ecs:UpdateCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ecs, function(region, rcb) {
            var listClusters = helpers.addSource(cache, source,
                ['ecs', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for ECS clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0, 'No ECS clusters found', region);
                return rcb();
            }

            var servicesWithIssues = [];
            var hasServices = false;

            for (var clusterArn of listClusters.data) {
                var listServices = helpers.addSource(cache, source,
                    ['ecs', 'listServices', region, clusterArn]);

                if (!listServices || listServices.err || !listServices.data || !listServices.data.length) {
                    helpers.addResult(results, 0,
                        'No ECS services found in cluster ', region, clusterArn);
                    continue;
                }

                hasServices = true;

                for (var serviceArn of listServices.data) {
                    var describeServices = helpers.addSource(cache, source,
                        ['ecs', 'describeServices', region, serviceArn]);

                    if (!describeServices || describeServices.err || !describeServices.data) {
                        helpers.addResult(results, 3,
                            'Unable to describe ECS service: ' + helpers.addError(describeServices), region, serviceArn);
                        continue;
                    }

                    if (!describeServices.data.services || !describeServices.data.services.length) {
                        helpers.addResult(results, 3,
                            'Unable to describe ECS service: no service data returned', region, serviceArn);
                        continue;
                    }

                    var service = describeServices.data.services[0];
                    if (!service) {
                        helpers.addResult(results, 3,
                            'Unable to describe ECS service: service object is empty', region, serviceArn);
                        continue;
                    }

                    var networkMode = service.networkConfiguration;
                    var assignPublicIp = null;

                    if (networkMode && networkMode.awsvpcConfiguration) {
                        assignPublicIp = networkMode.awsvpcConfiguration.assignPublicIp;
                        var assignPublicIpLower = assignPublicIp ? assignPublicIp.toLowerCase() : '';
                        if (assignPublicIpLower !== 'disabled') {
                            servicesWithIssues.push({
                                serviceArn: serviceArn,
                                serviceName: service.serviceName,
                                clusterArn: clusterArn,
                                assignPublicIp: assignPublicIp || 'not set (defaults to ENABLED)'
                            });
                        }
                    }
                }
            }

            if (servicesWithIssues.length > 0) {
                for (var item of servicesWithIssues) {
                    helpers.addResult(results, 2,
                        `ECS service "${item.serviceName}" has assignPublicIp set to ${item.assignPublicIp} instead of DISABLED`,
                        region, item.serviceArn);
                }
            } else if (hasServices) {
                helpers.addResult(results, 0,
                    'All ECS services with awsvpcConfiguration have assignPublicIp set to DISABLED',
                    region);
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

