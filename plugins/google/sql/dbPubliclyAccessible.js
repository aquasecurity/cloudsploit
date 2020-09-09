var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'DB Publicly Accessible',
    category: 'SQL',
    description: 'Ensures that SQL instances do not allow public access',
    more_info: 'Unless there is a specific business requirement, SQL instances should not have a public endpoint and should only be accessed from within a VPC.',
    link: 'https://cloud.google.com/sql/docs/mysql/authorize-networks',
    recommended_action: 'Ensure that SQL instances are configured to prohibit traffic from the public 0.0.0.0 global IP address.',
    apis: ['instances:sql:list'],
    compliance: {
        hipaa: 'SQL instances should only be launched in VPC environments and ' +
            'accessed through private endpoints. Exposing SQL instances to ' +
            'the public network may increase the risk of access from ' +
            'disallowed parties. HIPAA requires strict access and integrity ' +
            'controls around sensitive data.',
        pci: 'PCI requires backend services to be properly firewalled. ' +
            'Ensure SQL instances are not accessible from the Internet ' +
            'and use proper jump box access mechanisms.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instances.sql, function(region, rcb){
            let sqlInstances = helpers.addSource(
                cache, source, ['instances', 'sql', 'list', region]);

            if (!sqlInstances) return rcb();

            if (sqlInstances.err || !sqlInstances.data) {
                helpers.addResult(results, 3, 'Unable to query SQL instances: ' + helpers.addError(sqlInstances), region);
                return rcb();
            }

            if (!sqlInstances.data.length) {
                helpers.addResult(results, 0, 'No SQL instances found', region);
                return rcb();
            }
            var myIpConfig = {};
            sqlInstances.data.forEach(sqlInstance => {
                if (sqlInstance.instanceType != "READ_REPLICA_INSTANCE" &&
                    sqlInstance.settings &&
                    sqlInstance.settings.ipConfiguration) {
                    myIpConfig = sqlInstance.settings.ipConfiguration
                    if (myIpConfig.privateNetwork && !myIpConfig.ipv4Enabled) {
                        helpers.addResult(results, 0,
                            'SQL Instance is not publicly accessible', region, sqlInstance.name);
                    } else if (myIpConfig.ipv4Enabled &&
                                myIpConfig.authorizedNetworks) {
                                    var openNetwork = false;
                                    myIpConfig.authorizedNetworks.forEach(network => {
                                        if (network.value == '0.0.0.0/0') {
                                           openNetwork = true;
                                        }
                                    })
                                    if (openNetwork) {
                                        helpers.addResult(results, 2,
                                            'SQL Instance is publicly accessible by all IP addresses', region, sqlInstance.name);
                                    } else if (myIpConfig.authorizedNetworks.length){
                                        helpers.addResult(results, 1,
                                            'SQL Instance is publicly accessible by specific IP addresses', region, sqlInstance.name);
                                    } else {
                                        helpers.addResult(results, 0,
                                            'SQL Instance is not publicly accessible', region, sqlInstance.name);
                                    }
                                }
                }else if (sqlInstance.instanceType == "READ_REPLICA_INSTANCE"){
                }
            })

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
