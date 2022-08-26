var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Internet Gateways Associated with VPC',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure Internet Gateways are associated with at least one available VPC.',
    more_info: 'Internet Gateways allow communication between instances in VPC and the internet. They provide a target in VPC route tables for internet-routable traffic and also perform network address translation (NAT) for instances that have been assigned public IPv4 addresses. By default, AWS VPC has a limit of 5 internet gateways per region, so it is a best practice to make sure they are always associated with a VPC and remove any unused internet gateways.',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html',
    recommended_action: 'Check if Internet Gateways have VPC Attached to them.',
    apis: ['EC2:describeInternetGateways', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeInternetGateways = helpers.addSource(cache, source,
                ['ec2', 'describeInternetGateways', region]);

            if (!describeInternetGateways) return rcb();

            if (describeInternetGateways.err || !describeInternetGateways.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Internet Gateways: ${helpers.addError(describeInternetGateways)}`,
                    region);
                return rcb();
            }

            if (!describeInternetGateways.data.length) {
                helpers.addResult(results, 0,
                    'No Internet Gateways found', region);
                return rcb();
            }

            describeInternetGateways.data.forEach(function(gateway){
                let resource = `arn:${awsOrGov}:vpc:${region}:${accountId}:internet-gateway`;  
                if (gateway.Attachments && gateway.Attachments.length) {
                    for (var v in gateway.Attachments) {
                        var attachment = gateway.Attachments[v];
                        if (attachment.VpcId) {
                            helpers.addResult(results, 0,
                                'Internet Gateway is associated with VPC',
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                'Internet Gateway is not associated with VPC',
                                region, resource);
                        }
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Internet Gateway is not associated with VPC',
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};