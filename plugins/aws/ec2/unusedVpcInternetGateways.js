var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unused VPC Internet Gateways',
    category: 'EC2',
    description: 'Ensures that unused VPC Internet Gateways and Egress-Only Internet Gateways are removed.',
    more_info: 'Unused VPC Internet Gateways and Egress-Only Internet Gateways must be removed to avoid reaching the internet gateway limit.',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html',
    recommended_action: 'Remove the unused/detached Internet Gateways and Egress-Only Internet Gateways',
    apis: ['EC2:describeInternetGateways', 'EC2:describeEgressOnlyInternetGateways', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
    
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            async.parallel([
                function(lcb){
                    var describeInternetGateways = helpers.addSource(cache, source,
                        ['ec2', 'describeInternetGateways', region]);

                    if (!describeInternetGateways) return lcb();
                    
                    if (describeInternetGateways.err || !describeInternetGateways.data) {
                        helpers.addResult(results, 3,
                            `Unable to query for Internet Gateways: ${helpers.addError(describeInternetGateways)}`, region);
                        return lcb();
                    }

                    if (!describeInternetGateways.data.length) {
                        helpers.addResult(results, 0, 'No Internet Gateways found', region);
                    }
                    
                    let resource = `arn:${awsOrGov}:vpc:${region}:${accountId}:internet-gateway`;
                    loopGWForResults(describeInternetGateways, results, region, resource);

                    lcb();
                },
                function(lcb){
                    var describeEgressOnlyInternetGateways = helpers.addSource(cache, source,
                        ['ec2', 'describeEgressOnlyInternetGateways', region]);
                    
                    if (!describeEgressOnlyInternetGateways) return lcb();
                
                    if (describeEgressOnlyInternetGateways.err || !describeEgressOnlyInternetGateways.data) {
                        helpers.addResult(results, 3,
                            `Unable to query for Egress-Only Internet Gateways: ${helpers.addError(describeEgressOnlyInternetGateways)}`,
                            region);
                        return lcb();
                    }

                    if (!describeEgressOnlyInternetGateways.data.length) {
                        helpers.addResult(results, 0, 'No Egress-Only Internet Gateways found', region);
                    }

                    let resource = `arn:${awsOrGov}:vpc:${region}:${accountId}:egress-only-internet-gateway`;
                    loopGWForResults(describeEgressOnlyInternetGateways, results, region, resource, 'Egress-Only');

                    lcb();
                }
            ], function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};

function loopGWForResults(gateways, results, region, resource, type = '') {
    gateways.data.forEach(function(gateway){
        let gatewayId = gateway.EgressOnlyInternetGatewayId || gateway.InternetGatewayId;
        resource = `${resource}/${gatewayId}`;
        
        if(gateway.Attachments && gateway.Attachments.length) {
            helpers.addResult(results, 0,
                `${type} Internet Gateway "${gatewayId}" is in use`,
                region, resource);
        } else {
            helpers.addResult(results, 2,
                `${type} Internet Gateway "${gatewayId}" in not in use`,
                region, resource);
        }
    });
}