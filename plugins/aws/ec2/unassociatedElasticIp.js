var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unassociated Elastic IP Addresses',
    category: 'EC2',
    description: 'Ensures all EIPs are allocated to a resource to avoid accidental usage or reuse and to save costs',
    more_info: 'EIPs should be deleted if they are not in use to avoid extra charges.',
    recommended_action: 'Delete the unassociated Elastic IP',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html',
    apis: ['EC2:describeAddresses', 'STS:getCallerIdentity'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb) {
            var describeAddresses = helpers.addSource(cache, source,
                ['ec2', 'describeAddresses', region]);

            if (!describeAddresses) return rcb();

            if(describeAddresses.err || !describeAddresses.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Elastic IP Addresses: ${helpers.addError(describeAddresses)}`, region);
                return rcb();
            }

            if(!describeAddresses.data.length) {
                helpers.addResult(results, 0, 'No Elastic IP Addresses found', region);
                return rcb();
            }

            describeAddresses.data.forEach(function(elasticIp){
                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:eip/${elasticIp.AllocationId}`;

                if(elasticIp.AssociationId) {
                    helpers.addResult(results, 0, `Elastic IP address ${elasticIp.AllocationId} is associated to a resource`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2, `Elastic IP address ${elasticIp.AllocationId} is not associated to any resource`,
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};