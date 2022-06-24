var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EMR Cluster Desired Instance Type',
    category: 'EMR',
    domain: 'Compute',
    description: 'Ensure AWS Elastic MapReduce (EMR) clusters are using desired instance type.',
    more_info: 'EMR cluster desired instance should be enabled  to get the desired instance type.',
    link: 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-debugging.html',
    recommended_action: 'Modify EMR clusters to enable cluster logging',
    apis: ['EMR:listClusters', 'EMR:listInstanceGroups'],
    settings: {
        emr_desired_master_instance_type: {
            name: 'EMR Desired Master Instance Type',
            description: 'Comma-separated list of desired master instance types for EMR',
            regex: '^.*$',
            default: ''
        },
        emr_desired_core_instance_type: {
            name: 'EMR Desired Core Instance Type',
            description: 'Comma-separated list of desired core instance types for EMR',
            regex: '^.*$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {  
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);

        const emr_desired_master_instance_type = settings.emr_desired_master_instance_type || this.settings.emr_desired_master_instance_type.default;
        const emr_desired_core_instance_type = settings.emr_desired_core_instance_type || this.settings.emr_desired_core_instance_type.default;

        if (!emr_desired_master_instance_type.length && !emr_desired_core_instance_type.length) return callback(null, results, source);

        async.each(regions.emr, function(region, rcb) {
            const listClusters = helpers.addSource(cache, source,
                ['emr', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for EMR cluster: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (!listClusters.data.length){
                helpers.addResult(results, 0, 'No EMR cluster found', region);
                return rcb();
            }

            for (const cluster of listClusters.data) {
                if (!cluster.Id) continue;

                const resource = cluster.ClusterArn;

                const listInstanceGroups = helpers.addSource(cache, source,
                    ['emr', 'listInstanceGroups', region, cluster.Id]);

                if (!listInstanceGroups || listInstanceGroups.err ||
                    !listInstanceGroups.data || !listInstanceGroups.data.InstanceGroups) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for EMR cluster config: ' + helpers.addError(listInstanceGroups), region, resource);
                    continue;
                }

                const config = listInstanceGroups.data.InstanceGroups;
                const masterGroup = config.find(InstanceGroup => InstanceGroup.InstanceGroupType === 'MASTER');
                const coreGroup = config.find(InstanceGroup => InstanceGroup.InstanceGroupType === 'CORE');
                const masterInstanceType = masterGroup ? masterGroup.InstanceType : null;
                const coreInstanceType = coreGroup ? coreGroup.InstanceType : null;

                if (!masterInstanceType || !coreInstanceType) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for EMR cluster master or core instance type',
                        region, resource);
                    continue;
                }

                if ((masterInstanceType && !emr_desired_master_instance_type.includes(masterInstanceType)) &&
                    (coreInstanceType && !emr_desired_core_instance_type.includes(coreInstanceType))) {
                    helpers.addResult(results, 2,
                        `EMR cluster is using ${masterInstanceType} master and ${coreInstanceType} core instance types`,
                        region, resource);
                } else if (masterInstanceType && !emr_desired_master_instance_type.includes(masterInstanceType)) {
                    helpers.addResult(results, 2,
                        `EMR cluster is using ${masterInstanceType} master instance type`,
                        region, resource);
                } else if (coreInstanceType && !emr_desired_core_instance_type.includes(coreInstanceType)) {
                    helpers.addResult(results, 2,
                        `EMR cluster is using ${coreInstanceType} core instance type`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'EMR cluster is using allowed master and node instance types',
                        region, resource);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
