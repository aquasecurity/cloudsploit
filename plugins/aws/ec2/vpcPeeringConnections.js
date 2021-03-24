var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Cross Organization VPC Peering Connections',
    category: 'EC2',
    description: 'Ensures that VPC peering communication is only between AWS accounts, members of the same AWS Organization.',
    more_info: 'VPC peering communication should be only between AWS accounts to keep organization resources private and isolated.',
    recommended_action: 'Update VPC peering connections to allow connections to AWS Accounts, members of the same organization',
    link: 'https://docs.aws.amazon.com/vpc/latest/peering/working-with-vpc-peering.html',
    apis: ['Organizations:listAccounts', 'EC2:describeVpcPeeringConnections', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeVpcPeeringConnections = helpers.addSource(cache, source,
                ['ec2', 'describeVpcPeeringConnections', region]);

            if (!describeVpcPeeringConnections) return rcb();

            if (describeVpcPeeringConnections.err || !describeVpcPeeringConnections.data) {
                helpers.addResult(results, 3,
                    `Unable to query for VPC peering connections: ${helpers.addError(describeVpcPeeringConnections)}`, region);
                return rcb();
            }

            if (!describeVpcPeeringConnections.data.length) {
                helpers.addResult(results, 0,
                    'No VPC peering connections found', region);
                return rcb();
            }

            var listAccounts = helpers.addSource(cache, source,
                ['organizations', 'listAccounts', region]);

            if (!listAccounts || listAccounts.err || !listAccounts.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Organization Accounts: ${helpers.addError(listAccounts)}`, region);
                return rcb();
            }

            var organizationAccounts = [];
            if (listAccounts.data.length) {
                listAccounts.data.forEach(account => {
                    if (account.Arn && account.Id) {
                        organizationAccounts.push(account.Id);
                    }
                });
            }

            describeVpcPeeringConnections.data.forEach(connection => {
                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:vpc-peering-connection/${connection.VpcPeeringConnectionId}`;

                if (connection.RequesterVpcInfo &&
                    connection.RequesterVpcInfo.OwnerId &&
                    organizationAccounts.includes(connection.RequesterVpcInfo.OwnerId) &&
                    connection.AccepterVpcInfo &&
                    connection.AccepterVpcInfo.OwnerId &&
                    organizationAccounts.includes(connection.AccepterVpcInfo.OwnerId)) {
                    helpers.addResult(results, 0,
                        `VPC peering connection "${connection.VpcPeeringConnectionId}" does not allow communication outside organization accounts`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `VPC peering connection "${connection.VpcPeeringConnectionId}" allows communication outside organization accounts`,
                        region, resource);    
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};