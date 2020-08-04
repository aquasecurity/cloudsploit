var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EKS Kubernetes Version',
    category: 'EKS',
    description: 'Ensures the latest version of Kubernetes is installed on EKS clusters',
    more_info: 'EKS supports provisioning clusters from several versions of Kubernetes. Clusters should be kept up to date to ensure Kubernetes security patches are applied.',
    link: 'https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html',
    recommended_action: 'Upgrade the version of Kubernetes on all EKS clusters to the latest available version.',
    apis: ['EKS:listClusters', 'EKS:describeCluster', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var deprecatedVersions = {
            '1.10': '2019-07-22'
        };

        var outdatedVersions = {
            '1.11': '2019-03-28',
            '1.12': '2019-06-18'
        };

        async.each(regions.eks, function(region, rcb) {
            var listClusters = helpers.addSource(cache, source,
                ['eks', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for EKS clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if(listClusters.data.length === 0){
                helpers.addResult(results, 0, 'No EKS clusters present', region);
                return rcb();
            }

            for (var c in listClusters.data) {
                var clusterName = listClusters.data[c];
                var describeCluster = helpers.addSource(cache, source,
                    ['eks', 'describeCluster', region, clusterName]);

                var arn = 'arn:' + awsOrGov + ':eks:' + region + ':' + accountId + ':cluster/' + clusterName;

                if (!describeCluster || describeCluster.err || !describeCluster.data) {
                    helpers.addResult(
                        results, 3,
                        'Unable to describe EKS cluster: ' + helpers.addError(describeCluster),
                        region, arn);
                    continue;
                }

                if (describeCluster.data.cluster &&
                    describeCluster.data.cluster.version) {
                    var version = describeCluster.data.cluster.version;
                    if (deprecatedVersions[version]) {
                        helpers.addResult(results, 2,
                            'EKS cluster is running Kubernetes: ' + version + ' which was deprecated on: ' + deprecatedVersions[version],
                            region, arn);
                    } else if (outdatedVersions[version]) {
                        helpers.addResult(results, 1,
                            'EKS cluster is running Kubernetes: ' + version + ' which is currently outdated',
                            region, arn);
                    } else {
                        helpers.addResult(results, 0,
                            'EKS cluster is running a current version of Kubernetes: ' + version,
                            region, arn);
                    }
                } else {
                    helpers.addResult(results, 2, 'Unknown Kubernetes version found', region, arn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
