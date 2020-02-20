var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'DB Private Subnet Only',
    category: 'Database',
    description: 'Ensures that all database systems are in private subnets only.',
    more_info: 'Database systems in private subnets ensure that access to the database can ' +
        'only be from within the internal architecture, following security best practices.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Security/Reference/dbaas_security.htm',
    recommended_action: 'When creating a new database, ensure that that subnet it is being ' +
        'launched in is a private subnet.',
    apis: ['vcn:list', 'dbSystem:list', 'subnet:list'],
    compliance: {
        hipaa: 'DB systems should only be launched in private subnets and ' +
            'accessed through private endpoints. Exposing DB systems to ' +
            'the public network may increase the risk of access from ' +
            'disallowed parties. HIPAA requires strict access and integrity ' +
            'controls around sensitive data.',
        pci: 'PCI requires DB systems to be properly secured. Ensure ' +
            'DB systems are not accessible from the Internet and ' +
            'use proper jump box access mechanisms.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.dbSystem, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {
                var noSubnet = false;
                var noDbSystem = false;
                var badSubnetObj = {};

                const databases = helpers.addSource(cache, source,
                    ['dbSystem', 'list', region]);

                if (databases && ((databases.err && databases.err.length) || !databases.data)) {
                    helpers.addResult(results, 3,
                        'Unable to query for database systems: ' + helpers.addError(databases), region);

                } else if (databases && !databases.data.length) {
                    noDbSystem = true;

                } else if (databases) {

                    databases.data.forEach(database => {
                        if (database.lifecycleState === "AVAILABLE") {
                            if (database.subnetId) {
                                if (!badSubnetObj[database.subnetId]) {
                                    badSubnetObj[database.subnetId] = [];
                                }
                                badSubnetObj[database.subnetId].push(database.id);
                            }
                        }
                    });
                }

                const subnets = helpers.addSource(cache, source,
                    ['subnet', 'list', region]);

                if (subnets && ((subnets.err && subnets.err.length) || !subnets.data)) {
                    helpers.addResult(results, 3,
                        'Unable to query for subnets: ' + helpers.addError(subnets), region);

                } else if (subnets && !subnets.data.length) {
                    noSubnet = true;

                } else if (subnets) {
                    var noPublicSubnets = true;
                    subnets.data.forEach(subnet => {
                        if (subnet.id) {
                            if (!subnet.prohibitPublicIpOnVnic) {
                                if (badSubnetObj &&
                                    badSubnetObj[subnet.id]) {
                                    var badDbSystemsStr =  badSubnetObj[subnet.id].join(", ");
                                    // not sure whether to use 'this', 'the', or 'a' to refer to the subnet
                                    helpers.addResult(results, 2,
                                        `The following db systems use the public subnet: ${badDbSystemsStr}`, region, subnet.id);
                                    noPublicSubnets = false;
                                }
                            }
                        }
                    });
                }

                if (noSubnet && noDbSystem) {
                    helpers.addResult(results, 0, 'No database systems or subnets present', region);
                } else if (noDbSystem) {
                    helpers.addResult(results, 0, 'No database systems found', region);
                } else if (noSubnet) {
                    helpers.addResult(results, 0, 'No subnets found', region);
                } else if (noPublicSubnets) {
                    helpers.addResult(results, 0, 'All db systems are in private subnets', region);
                }


            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};