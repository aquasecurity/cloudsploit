var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC Endpoint Exposed',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure Amazon VPC endpoints are not publicly exposed.',
    more_info: 'VPC endpoints should not be publicly accessible in order to avoid any unsigned requests made to the services inside VPC.',
    recommended_action: 'Update VPC endpoint access policy in order to stop any unsigned requests',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html',
    apis: ['EC2:describeVpcEndpoints', 'EC2:describeSubnets', 'EC2:describeRouteTables', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeVpcEndpoints = helpers.addSource(cache, source,
                ['ec2', 'describeVpcEndpoints', region]);

            if (!describeVpcEndpoints) return rcb();

            if (describeVpcEndpoints.err || !describeVpcEndpoints.data) {
                helpers.addResult(results, 3,
                    'Unable to query for VPC endpoints: ' + helpers.addError(describeVpcEndpoints), region);
                return rcb();
            }

            if (!describeVpcEndpoints.data.length) {
                helpers.addResult(results, 0,
                    'No VPC endpoins present', region);
                return rcb();
            }

            var describeSubnets = helpers.addSource(cache, {},
                ['ec2', 'describeSubnets', region]);

            if (!describeSubnets || describeSubnets.err || !describeSubnets.data) {
                helpers.addResult(results, 3,
                    'Unable to query for VPC subnets: ' + helpers.addError(describeSubnets), region);
                return rcb();
            }

            var describeRouteTables = helpers.addSource(cache, {},
                ['ec2', 'describeRouteTables', region]);
        
            if (!describeRouteTables || describeRouteTables.err || !describeRouteTables.data) {
                helpers.addResult(results, 3,
                    'Unable to query for route tables: ' + helpers.addError(describeRouteTables), region);
                return rcb();
            }

            var subnetRouteTableMap = helpers.getSubnetRTMap(describeSubnets.data, describeRouteTables.data);
            var privateSubnets = helpers.getPrivateSubnets(subnetRouteTableMap, describeSubnets.data, describeRouteTables.data);

            for (var endpoint of describeVpcEndpoints.data) {
                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:vpc-endpoint/${endpoint.VpcEndpointId}`;
                if (endpoint.VpcEndpointType && endpoint.VpcEndpointType.toLowerCase() == 'gateway') {
                    helpers.addResult(results, 0,
                        `VPC endpoint is of ${endpoint.VpcEndpointId} is of Gateway type`, region, resource);
                    continue;
                }

                if (endpoint.SubnetIds && endpoint.SubnetIds.length) {
                    if (endpoint.SubnetIds.find(subnetId => privateSubnets.includes(subnetId))) {
                        helpers.addResult(results, 0,
                            'VPC endpoint is behind private subnet', region, resource);
                        continue;
                    }
                }

                var statements = helpers.normalizePolicyDocument(endpoint.PolicyDocument);
                var publicEndpoint = false;

                for (var s in statements) {
                    var statement = statements[s];
                    
                    if (statement.Effect == 'Allow') {
                        if (helpers.globalPrincipal(statement.Principal)) {
                            publicEndpoint = true;
                            break;
                        }
                    }
                }

                if (!publicEndpoint) {
                    helpers.addResult(results, 0,
                        `VPC endpoint ${endpoint.VpcEndpointId} is not exposed`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `VPC endpoint ${endpoint.VpcEndpointId} is publicly exposed`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
