var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EKS Secrets Encrypted',
    category: 'EKS',
    domain: 'Containers',
    description: 'Ensures EKS clusters are configured to enable envelope encryption of Kubernetes secrets using KMS.',
    more_info: 'Amazon EKS clusters should be configured to enable envelope encryption for Kubernetes secrets to adhere to security best practice for applications that store sensitive data.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/',
    recommended_action: 'Modify EKS clusters to enable envelope encryption for Kubernetes secrets',
    apis: ['EKS:listClusters', 'EKS:describeCluster', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.eks, function(region, rcb) {
            var listClusters = helpers.addSource(cache, source,
                ['eks', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for EKS clusters: ${helpers.addError(listClusters)}`, region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0, 'No EKS clusters found', region);
                return rcb();
            }

            for (var clusterName of listClusters.data) {
                var describeCluster = helpers.addSource(cache, source,
                    ['eks', 'describeCluster', region, clusterName]);

                var arn = `arn:${awsOrGov}:eks:${region}:${accountId}:cluster/${clusterName}`;

                if (!describeCluster || describeCluster.err || !describeCluster.data || !describeCluster.data.cluster) {
                    helpers.addResult(
                        results, 3,
                        'Unable to describe EKS cluster: ' + helpers.addError(describeCluster),
                        region, arn);
                    continue;
                }

                var encryptionEnabled = false;
                if (describeCluster.data.cluster.encryptionConfig &&
                    describeCluster.data.cluster.encryptionConfig.length) {
                    for (var config of describeCluster.data.cluster.encryptionConfig) {
                        if (config.resources &&
                            config.resources.includes('secrets') &&
                            config.provider &&
                            config.provider.keyArn &&
                            config.provider.keyArn.length) {
                            encryptionEnabled = true;
                            break;
                        }
                    }

                    if (encryptionEnabled) {
                        helpers.addResult(results, 0,
                            `Envelope encryption of Kubernetes secrets is enabled for EKS cluster "${clusterName}"`,
                            region, arn);
                    } else {
                        helpers.addResult(results, 2,
                            `Envelope encryption of Kubernetes secrets is not enabled for EKS cluster "${clusterName}"`,
                            region, arn);
                    }
                } else {
                    helpers.addResult(results, 2,
                        `Envelope encryption of Kubernetes secrets is not enabled for cluster "${clusterName}"`,
                        region, arn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
