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

            for (var clusterArn of listClusters.data) {
                var listServices = helpers.addSource(cache, source,
                    ['ecs', 'listServices', region, clusterArn]);

                if (!listServices || listServices.err || !listServices.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for ECS services: ' + helpers.addError(listServices), region, clusterArn);
                    continue;
                }

                if (!listServices.data.length) {
                    helpers.addResult(results, 0,
                        'No ECS services found in cluster', region, clusterArn);
                    continue;
                }

                for (var serviceArn of listServices.data) {
                    var describeServices = helpers.addSource(cache, source,
                        ['ecs', 'describeServices', region, serviceArn]);

                    if (!describeServices || describeServices.err || !describeServices.data) {
                        helpers.addResult(results, 3,
                            'Unable to describe ECS service: ' + helpers.addError(describeServices), region, serviceArn);
                        continue;
                    }

                    var service = describeServices.data.services[0];
                    var networkMode = service.networkConfiguration;
                    var assignPublicIp = null;

                    if (networkMode && networkMode.awsvpcConfiguration) {
                        assignPublicIp = networkMode.awsvpcConfiguration.assignPublicIp;
                        var assignPublicIpLower = assignPublicIp ? assignPublicIp.toLowerCase() : '';
                        if (assignPublicIpLower !== 'disabled') {
                            helpers.addResult(results, 2,
                                'ECS service does not have assignPublicIp set to DISABLED',
                                region, serviceArn);
                        } else {
                            helpers.addResult(results, 0,
                                'ECS service has assignPublicIp set to DISABLED',
                                region, serviceArn);
                        }
                    }
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};


