var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'DB Publicly Accessible',
    category: 'SQL',
    description: 'Ensures that SQL instances have a failover replica to be cross-AZ for high availability.',
    more_info: 'Creating SQL instances in with a single AZ creates a single point of failure for all systems relying on that database. All SQL instances should be created in multiple AZs to ensure proper failover.',
    link: 'https://cloud.google.com/sql/docs/mysql/instance-settings',
    recommended_action: '1. Enter the SQL category of the Google Console. 2. Select the instance. 3. Select the Replicas tab. 4. Select Create Failover Replica and follow the prompts.',
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