var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EKS Security Groups',
    category: 'EKS',
    description: 'Ensures the EKS control plane only allows inbound traffic on port 443.',
    more_info: 'The EKS control plane only requires port 443 access. Security groups for the control plane should not add additional port access.',
    link: 'https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html',
    recommended_action: 'Configure security groups for the EKS control plane to allow access only on port 443.',
    apis: ['EKS:listClusters', 'EKS:describeCluster', 'EC2:describeSecurityGroups', 'STS:getCallerIdentity'],

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
                    'Unable to query for EKS clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if(listClusters.data.length === 0){
                helpers.addResult(results, 0, 'No EKS clusters present', region);
                return rcb();
            }

            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups || describeSecurityGroups.err ||
                !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to describe security group rules: ' + helpers.addError(describeSecurityGroups),
                    region);
                return rcb();
            }

            var sgMap = {};
            for (var s in describeSecurityGroups.data) {
                var sg = describeSecurityGroups.data[s];
                sgMap[sg.GroupId] = [];
                for (var i in sg.IpPermissions) {
                    var perm = sg.IpPermissions[i];
                    if (perm.FromPort && perm.ToPort &&
                        (perm.FromPort !== 443 || perm.ToPort !== 443)) {
                        sgMap[sg.GroupId].push([perm.FromPort, perm.ToPort].join(':'));
                    } else if (!perm.FromPort && !perm.ToPort) {
                        sgMap[sg.GroupId].push([0, 65535].join(':'));
                    }
                }
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
                    describeCluster.data.cluster.resourcesVpcConfig &&
                    describeCluster.data.cluster.resourcesVpcConfig.securityGroupIds &&
                    describeCluster.data.cluster.resourcesVpcConfig.securityGroupIds.length) {
                    
                    var groups = describeCluster.data.cluster.resourcesVpcConfig.securityGroupIds;
                    var effectiveInbound = [];
                    for (s in groups) {
                        var group = groups[s];
                        if (sgMap[group]) effectiveInbound = effectiveInbound.concat(sgMap[group]);
                    }

                    if (effectiveInbound.length) {
                        helpers.addResult(results, 2, 'EKS control plane security groups allow additional access on unnecessary port ranges: ' + effectiveInbound.join(', '), region, arn);
                    } else {
                        helpers.addResult(results, 0, 'EKS control plane security groups do not contain unnecessary ports', region, arn);
                    }
                } else {
                    helpers.addResult(results, 1, 'EKS control plane does not have security groups configured', region, arn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
