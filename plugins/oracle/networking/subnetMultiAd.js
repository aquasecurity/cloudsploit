var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Subnet Multi AD',
    category: 'Networking',
    description: 'Detects subnets that are not regional',
    more_info: 'Creating a regional subnet ensures a highly available system. Regional subnets span across multiple availability domains increasing the availability and durability of the resources launched within it.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVCNs.htm',
    recommended_action: 'when creating a new subnet, under subnet type, ensure that regional is selected.',
    apis: ['vcn:list','subnet:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.loadBalancer, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var subnets = helpers.addSource(cache, source,
                    ['subnet', 'list', region]);

                if (!subnets) return rcb();

                if ((subnets.err && subnets.err.length) || !subnets.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for subnets: ' + helpers.addError(subnets), region);
                    return rcb();
                }

                if (!subnets.data.length) {
                    helpers.addResult(results, 0, 'No subnets found', region);
                    return rcb();
                }

                var badSubnetObj = {};
                var goodSubnetObj = {};

                subnets.data.forEach(subnet  => {
                    if (subnet.availabilityDomain) {
                        if(!badSubnetObj[subnet.vcnId]) {
                            badSubnetObj[subnet.vcnId] = 1;
                        } else {
                            badSubnetObj[subnet.vcnId]++
                        }
                    } else {
                        if(!goodSubnetObj[subnet.vcnId]) {
                            goodSubnetObj[subnet.vcnId] = 1;
                        } else {
                            goodSubnetObj[subnet.vcnId]++
                        }
                    }
                });
                if (Object.keys(badSubnetObj).length) {
                    for (var bad in badSubnetObj) {
                        helpers.addResult(results, 2, `${badSubnetObj[bad]} subnets in the VCN are not regional`, region, bad);
                    }
                }
                if (Object.keys(goodSubnetObj).length) {
                    for (var good in goodSubnetObj) {
                        helpers.addResult(results, 0, 'The subnets in the VCN are regional', region, good);
                    }
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};