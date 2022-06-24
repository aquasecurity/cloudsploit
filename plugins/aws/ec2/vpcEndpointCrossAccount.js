var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC Endpoint Cross Account Access',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensures that Amazon VPC endpoints do not allow unknown cross account access.',
    more_info: 'VPC endpoints should not allow unknown cross account access to avoid any unsigned requests made to the services inside VPC.',
    recommended_action: 'Update VPC endpoint access policy in order to remove untrusted cross account access',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html',
    apis: ['EC2:describeVpcEndpoints', 'STS:getCallerIdentity'],
    settings: {
        vpc_trusted_cross_account_arns: {
            name: 'VPC Trusted Cross Account ARNs',
            description: 'A comma-separated list of trusted cross account ARNs i.e. \'arn:aws:iam::000111222333:user/user1,arn:aws:iam::000111222333:user/user2\'',
            regex: '^.*$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var vpc_trusted_cross_account_arns =  settings.vpc_trusted_cross_account_arns || this.settings.vpc_trusted_cross_account_arns.default;
        vpc_trusted_cross_account_arns = vpc_trusted_cross_account_arns.split(',');

        async.each(regions.ec2, function(region, rcb){
            var describeVpcEndpoints = helpers.addSource(cache, source,
                ['ec2', 'describeVpcEndpoints', region]);

            if (!describeVpcEndpoints) return rcb();

            if (describeVpcEndpoints.err || !describeVpcEndpoints.data) {
                helpers.addResult(results, 3,
                    `Unable to query for VPC endpoints: ${helpers.addError(describeVpcEndpoints)}`, region);
                return rcb();
            }

            if (!describeVpcEndpoints.data.length) {
                helpers.addResult(results, 0,
                    'No VPC endpoins found', region);
                return rcb();
            }

            describeVpcEndpoints.data.forEach(endpoint =>{
                if (!endpoint.VpcEndpointId) return;

                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:vpc-endpoint/${endpoint.VpcEndpointId}`;
                var unallowedCrossAccounts = [];

                if (endpoint.PolicyDocument) {
                    var statements = helpers.normalizePolicyDocument(endpoint.PolicyDocument);

                    for (var statement of statements) {
                        if (statement.Effect && statement.Effect.toUpperCase() === 'ALLOW' && statement.Principal) {
                            var principals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);

                            for (var principal of principals) {
                                if (!vpc_trusted_cross_account_arns.includes(principal) &&
                                    !unallowedCrossAccounts.includes(principal)) {
                                    unallowedCrossAccounts.push(principal);
                                }
                            }
                        }
                    }
                }

                if (!unallowedCrossAccounts.length) {
                    helpers.addResult(results, 0,
                        `VPC endpoint ${endpoint.VpcEndpointId} does not allow unknown cross account access`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `VPC endpoint ${endpoint.VpcEndpointId} allows cross account access to these principals: ${unallowedCrossAccounts.join(', ')}`,
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};