var async   = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EMR Instances Counts',
    category: 'EMR',
    domain: 'Compute',
    description: 'Ensure that the number of EMR cluster instances provisioned in your AWS account has not reached the desired threshold established by your organization.',
    more_info: 'Setting threshold for the number of EMR cluster instances provisioned within your AWS account will help to manage EMR compute resources and' +
        'prevent unexpected charges on your AWS bill.',
    link: 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-view-clusters.html',
    recommended_action: 'Ensure that the number of running EMR cluster instances matches the expected count. If instances are launched above the threshold, investigate to ensure they are legitimate.',
    apis: ['EMR:listClusters', 'EMR:listInstanceGroups'],
    settings: {
        emr_instance_count_global_threshold: {
            name: 'EMR Instance Count Global Threshold',
            description: 'Checks for the number of running EMR instances across all regions and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 200
        },
        emr_instance_count_regional_threshold: {
            name: 'EMR Instance Count Regional Threshold',
            description: 'Checks for the number of running EMR instances per region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            emr_instance_count_global_threshold: settings.emr_instance_count_global_threshold || this.settings.emr_instance_count_global_threshold.default,
            emr_instance_count_regional_threshold: settings.emr_instance_count_regional_threshold || this.settings.emr_instance_count_regional_threshold.default
        };

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var instanceCountGlobal = 0;

        async.each(regions.emr, function(region, rcb){
            var listClusters = helpers.addSource(cache, source,
                ['emr', 'listClusters', region]);
                
            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EMR clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0, 'No EMR clusters found', region);
                return rcb();
            }

            let instanceCount = 0;

            for (const cluster of listClusters.data) {
                if (!cluster.Id) continue;

                const resource = cluster.ClusterArn;

                const listInstanceGroups = helpers.addSource(cache, source,
                    ['emr', 'listInstanceGroups', region, cluster.Id]);

                if (!listInstanceGroups || listInstanceGroups.err ||
                    !listInstanceGroups.data || !listInstanceGroups.data.InstanceGroups) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for EMR cluster instance groups: ' + helpers.addError(listInstanceGroups), region, resource);
                    continue;
                }

                const instanceGroups = listInstanceGroups.data.InstanceGroups;
                const masterGroup = instanceGroups.find(InstanceGroup => InstanceGroup.InstanceGroupType === 'MASTER');
                const coreGroup = instanceGroups.find(InstanceGroup => InstanceGroup.InstanceGroupType === 'CORE');
                const masterInstanceCount = masterGroup ? masterGroup.RunningInstanceCount : 0;
                const coreInstanceCount = coreGroup ? coreGroup.RunningInstanceCount : 0;

                if (masterInstanceCount) {
                    instanceCountGlobal += masterInstanceCount;
                    instanceCount += masterInstanceCount;
                }
                if (coreInstanceCount){
                    instanceCountGlobal += coreInstanceCount;
                    instanceCount += coreInstanceCount;
                }
            }

            const regionThreshold = config.emr_instance_count_regional_threshold;

            if (instanceCount > config.emr_instance_count_regional_threshold) {
                helpers.addResult(results, 2,
                    instanceCount + ' EMR instances running in ' + region + ' region, exceed limit of: ' + regionThreshold,
                    region);
            } else {
                helpers.addResult(results, 0,
                    instanceCount + ' EMR instances in the region are within the regional expected count of: ' + regionThreshold, region);
            }

            rcb();
        }, function() {
            var globalThreshold = config.emr_instance_count_global_threshold;

            if (instanceCountGlobal > globalThreshold) {
                helpers.addResult(results, 2,
                    instanceCountGlobal + ' EMR instances running in all regions, exceed limit of: ' + globalThreshold, 'global');
            } else {
                helpers.addResult(results, 0,
                    instanceCountGlobal + ' EMR instances in the account are within the global expected count of: ' + globalThreshold, 'global');
            }
            callback(null, results, source);
        });
    }
};

