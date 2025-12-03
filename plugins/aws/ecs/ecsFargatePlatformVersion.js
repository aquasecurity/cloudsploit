var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECS Fargate Platform Version',
    category: 'ECS',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures that Amazon ECS Fargate services are using the latest Fargate platform version.',
    more_info: 'Using the latest Fargate platform version ensures services benefit from up-to-date security patches, performance improvements, and feature updates. Services should use LATEST to automatically receive the most recent platform version.',
    link: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform_versions.html',
    recommended_action: 'Update ECS Fargate services to use the latest platform version (LATEST) to ensure they benefit from the latest security enhancements and features.',
    apis: ['ECS:listClusters', 'ECS:listServices', 'ECS:describeServices'],
    realtime_triggers: ['ecs:CreateCluster', 'ecs:CreateService', 'ecs:UpdateService', 'ecs:DeleteService', 'ecs:DeleteCluster'],
    run: function(cache, settings, callback){
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ecs, function(region, rcb){

            var listClusters = helpers.addSource(cache, source,
                ['ecs', 'listClusters', region]);
            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for ECS clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0, 'No ECS clusters present', region);
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

                    if (!describeServices.data.services || !describeServices.data.services.length) {
                        helpers.addResult(results, 3,
                            'Unable to describe ECS service: no service data returned', region, serviceArn);
                        continue;
                    }

                    var service = describeServices.data.services[0];

                    if (!service) continue;

                    var isFargate = false;
                    if (service.launchType && service.launchType.toLowerCase() === 'fargate') {
                        isFargate = true;
                    } else if (service.platformVersion) {
                        isFargate = true;
                    } else if (service.capacityProviderStrategy && service.capacityProviderStrategy.length > 0) {
                        for (var cp of service.capacityProviderStrategy) {
                            if (cp.capacityProvider && cp.capacityProvider.toLowerCase().indexOf('fargate') !== -1) {
                                isFargate = true;
                                break;
                            }
                        }
                    }

                    if (!isFargate) {
                        helpers.addResult(results, 0,
                            'ECS service is not a Fargate service',
                            region, serviceArn);
                        continue;
                    }

                    var platformVersion = service.platformVersion;
                    var platformVersionLower = platformVersion ? platformVersion.toLowerCase() : '';

                    if (platformVersionLower !== 'latest') {
                        helpers.addResult(results, 2,
                            'ECS Fargate service is not using the latest platform version',
                            region, serviceArn);
                    } else {
                        helpers.addResult(results, 0,
                            'ECS Fargate service is using the latest platform version (LATEST)',
                            region, serviceArn);
                    }
                }
            }
            rcb();
        },
        function(){
            callback(null, results, source);
        });
    }
};

