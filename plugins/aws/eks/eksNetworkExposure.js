var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Internet Exposure',
    category: 'EKS',
    domain: 'Containers',
    severity: 'Info',
    description: 'Check if EKS clusters are exposed to the internet.',
    more_info: 'EKS clusters exposed to the internet are vulnerable to unauthorized access, potential data loss, and increased cyberattack risks. Securing access to the EKS API server, worker nodes, and associated resources by configuring security groups, NACLs, and using private subnets is essential for minimizing exposure.',
    link: 'https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html',
    recommended_action: 'Restrict public access to the EKS API server and worker nodes by ensuring proper configuration of API endpoint access, security groups, and NACLs. Utilize private subnets and NAT gateways where appropriate for worker node traffic.',
    apis: ['EKS:listClusters', 'EKS:describeCluster', 'STS:getCallerIdentity', 'EC2:describeSecurityGroups', 'EC2:describeNetworkInterfaces', 'EC2:describeSubnets',
        'EC2:describeRouteTables'],
    realtime_triggers: ['eks:CreateCluster', 'eks:updateClusterConfig', 'eks:DeleteCluster','ec2:CreateNetworkAcl', 'ec2:ReplaceNetworkAclEntry', 'ec2:ReplaceNetworkAclAssociation',
        'ec2:DeleteNetworkAcl', 'ec2:CreateSecurityGroup', 'ec2:AuthorizeSecurityGroupIngress','ec2:ModifySecurityGroupRules','ec2:RevokeSecurityGroupIngress',
        'ec2:DeleteSecurityGroup'],

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

                describeCluster.data.arn = arn;

                if (describeCluster.data.cluster) {
                    let cluster = describeCluster.data.cluster;
                    let securityGroups = [];
                    if (cluster.resourcesVpcConfig) {
                        if (cluster.resourcesVpcConfig.clusterSecurityGroupId) {
                            securityGroups.push(cluster.resourcesVpcConfig.clusterSecurityGroupId);
                        }
                        if (cluster.resourcesVpcConfig.securityGroupIds) {
                            securityGroups = securityGroups.concat(cluster.resourcesVpcConfig.securityGroupIds);
                        }
                        let internetExposed = helpers.checkNetworkExposure(cache, source, cluster.resourcesVpcConfig.subnetIds, securityGroups, [], region, results, cluster);
                        if (internetExposed && internetExposed.length) {
                            helpers.addResult(results, 2, `EKS cluster is exposed to the internet through ${internetExposed}`, region, arn);
                        } else {
                            helpers.addResult(results, 0, 'EKS cluster is not exposed to the internet', region, arn);
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
