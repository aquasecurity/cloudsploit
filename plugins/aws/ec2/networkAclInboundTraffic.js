var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unrestricted Network ACL Inbound Traffic',
    category: 'EC2',
    domain: 'Compute',
    severity: 'High',
    description: 'Ensures that no Amazon Network ACL allows inbound/ingress traffic to remote administration ports.',
    more_info: 'Amazon Network ACL should not allow inbound/ingress traffic to remote administration ports to avoid unauthorized access at the subnet level.',
    recommended_action: 'Update Network ACL to allow inbound/ingress traffic to specific port ranges only',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html',
    apis: ['EC2:describeNetworkAcls', 'STS:getCallerIdentity'],
    compliance: {
        cis1: '5.1 Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports',
    },
    realtime_triggers: ['ec2:CreateNetworkAcl', 'ec2:ReplaceNetworkAclEntry', 'ec2:DeleteNetworkAcl'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeNetworkAcls = helpers.addSource(cache, source,
                ['ec2', 'describeNetworkAcls', region]);

            if (!describeNetworkAcls) return rcb();

            if (describeNetworkAcls.err || !describeNetworkAcls.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Network ACLs: ${helpers.addError(describeNetworkAcls)}`, region);
                return rcb();
            }

            if (!describeNetworkAcls.data.length) {
                helpers.addResult(results, 0,
                    'No Network ACLs found', region);
                return rcb();
            }

            describeNetworkAcls.data.forEach(acl =>{
                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:network-acl/${acl.NetworkAclId}`;
                var unrestrictedAcl = false;

                if (acl.Entries && acl.Entries.length) {
                    for (var entry of acl.Entries) {
                        if (!entry.Egress && disAllowedPorRange(entry.PortRange) && entry.RuleAction.toUpperCase() === 'ALLOW' && entry.CidrBlock==='0.0.0.0/0') {
                            unrestrictedAcl = true;
                            break;
                        }
                    }
                }

                if (!unrestrictedAcl) {
                    helpers.addResult(results, 0,
                        `Network ACL "${acl.NetworkAclId}" does not allow unrestricted access`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Network ACL "${acl.NetworkAclId}" allows unrestricted access`,
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

function disAllowedPorRange(range) {
    const allowedPorts = [22, 3389, 80, 443, 53];

    if (!range) return true;

    for (const port of allowedPorts) {
        if (port >= range.From && port <= range.To) return true;
    }

    return false;
}
