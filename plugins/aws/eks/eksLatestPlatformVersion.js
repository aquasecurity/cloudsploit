var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EKS Latest Platform Version',
    category: 'EKS',
    domain: 'Containers',
    severity: 'Low',
    description: 'Ensure that EKS clusters are using latest platform version.',
    more_info: 'Amazon EKS platform versions represent the capabilities of the Amazon EKS cluster control plane, such as which Kubernetes API server flags are enabled, as well as the current Kubernetes patch version.'+
    'Clusters should be kept up to date of latest platforms to ensure Kubernetes security patches are applied.',
    link: 'https://docs.aws.amazon.com/eks/latest/userguide/platform-versions.html',
    recommended_action: 'Check for the version on all EKS clusters to be the latest platform version.',
    apis: ['EKS:listClusters', 'EKS:describeCluster', 'STS:getCallerIdentity'],
    realtime_triggers: ['eks:CreateCluster', 'eks:UpdateClusterVersion', 'eks:DeleteCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var latestVersions = {
            '1.29':6,
            '1.28':12,
            '1.27': 16,
            '1.26': 17,
            '1.25': 18,
            '1.24': 21,
            '1.23': 23,
            '1.22': 13,
            '1.21': 18,
        };

        var deprecatedVersions = {
            '1.10': '2019-07-22',
            '1.11': '2019-11-04',
            '1.12': '2020-05-11',
            '1.13': '2020-06-30',
            '1.14': '2020-12-08',
            '1.15': '2021-05-03',
            '1.16': '2021-09-27',
            '1.17': '2021-11-02',
            '1.18': '2022-03-31',
            '1.19': '2022-08-01',
            '1.20': '2022-11-01',
            '1.21': '2023-02-16',
            '1.22': '2023-06-04',
            '1.23': '2023-10-01',
            '1.24': '2024-01-01',
            '1.25': '2024-05-01',
            '1.26': '2024-06-11',
            '1.27': '2024-07-24',
            '1.28': '2024-11-26',
            '1.29': '2025-03-23'
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

            if (listClusters.data.length === 0){
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
                    describeCluster.data.cluster.version &&
                    describeCluster.data.cluster.platformVersion) {
                    var version = describeCluster.data.cluster.version;
                    let versionLatestPlatform = (latestVersions[version]) ? latestVersions[version] : null;
                    
                    let platform = describeCluster.data.cluster.platformVersion;
                    let platformVersion = platform.replace('eks.', '');

                    if (versionLatestPlatform) {
                        if (parseInt(platformVersion) >= versionLatestPlatform) {
                            helpers.addResult(results, 0,
                                'EKS cluster is running latest EKS platform version',
                                region, arn);
                        } else {
                            helpers.addResult(results, 2,
                                'EKS cluster is not running latest EKS platform version',
                                region, arn);
                        }
                    } else if (deprecatedVersions[version]){
                        helpers.addResult(results, 0,
                            'EKS cluster using deprecated EKS version',
                            region, arn);
                    } else {
                        helpers.addResult(results, 3, 'EKS cluster is using unknown EKS version', region, arn);
                    }
                } else {
                    helpers.addResult(results, 3, 'Unable to query cluster EKS version or platform version', region, arn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};