var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Managed NAT Gateway In Use',
    category: 'EC2',
    description: 'Ensure AWS VPC Managed NAT (Network Address Translation) Gateway service is enabled for high availability (HA).',
    more_info: 'VPCs should use highly available Managed NAT Gateways in order to enable EC2 instances to connect to the internet or with other AWS components.',
    link: 'https://aws.amazon.com/blogs/aws/new-managed-nat-network-address-translation-gateway-for-aws/',
    recommended_action: 'Update VPCs to use Managed NAT Gateways instead of NAT instances',
    apis: ['EC2:describeVpcs', 'EC2:describeNatGateways', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
        
        var foundVpcIds = [];

        async.each(regions.ec2, function(region, rcb){
            var describeVpcs = helpers.addSource(cache, source,
                ['ec2', 'describeVpcs', region]);
            
            if (!describeVpcs) return rcb();

            if (describeVpcs.err || !describeVpcs.data) {
                helpers.addResult(results, 3,
                    `Unable to query for VPCs: ${helpers.addError(describeVpcs)}`, region);
                return rcb();
            }

            if (!describeVpcs.data.length) {
                helpers.addResult(results, 0, 'No AWS VPCs found', region);
                return rcb();
            }

            var describeNatGateways = helpers.addSource(cache, source,
                ['ec2', 'describeNatGateways', region]);

            if (!describeNatGateways || describeNatGateways.err || !describeNatGateways.data) {
                helpers.addResult(results, 3,
                    `Unable to query for NAT Gateways: ${helpers.addError(describeNatGateways)}`, region);
                return rcb();
            }

            if (describeNatGateways.data.length) {
                describeNatGateways.data.forEach(function(nat){
                    if(nat.VpcId && !foundVpcIds.includes(nat.VpcId)) {
                        foundVpcIds.push(nat.VpcId);
                    }
                });
            }

            describeVpcs.data.forEach(function(vpc){
                var resource = `arn:${awsOrGov}:vpc:${region}:${accountId}:/vpc/${vpc.VpcId}`;

                if (foundVpcIds.includes(vpc.VpcId)) {
                    helpers.addResult(results, 0,
                        `VPC "${vpc.VpcId}" is using managed NAT Gateway`,
                        region, resource);
                }
                else {
                    helpers.addResult(results, 2,
                        `VPC "${vpc.VpcId}" is not using managed NAT Gateway`,
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};