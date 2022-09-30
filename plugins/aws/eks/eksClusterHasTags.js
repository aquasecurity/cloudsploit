var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EKS Cluster Has Tags',
    category: 'EKS',
    domain: 'Containers',
    description: 'Ensure that AWS EKS Clusters have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/eks/latest/userguide/eks-using-tags.html',
    recommended_action: 'Modify EKS Cluster and add tags.',
    apis: ['EKS:listClusters', 'ResourceGroupsTaggingAPI:getResources', 'STS:getCallerIdentity'],

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
                helpers.addResult(results, 3,
                    'Unable to query for EKS clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0, 'No EKS clusters present', region);
                return rcb();
            }

            const ARNList = [];
            for (var clusterName of listClusters.data) {
                var arn = 'arn:' + awsOrGov + ':eks:' + region + ':' + accountId + ':cluster/' + clusterName;
                ARNList.push(arn);
            }
            
            helpers.checkTags(cache,'EKS cluster', ARNList, region, results);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
