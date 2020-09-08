var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Default VPC In Use',
    category: 'VPC Network',
    description: 'Determines whether the default VPC is being used for launching VM instances',
    more_info: 'The default VPC should not be used in order to avoid launching multiple services in the same network which may not require connectivity. Each application, or network tier, should use its own VPC.',
    link: 'https://cloud.google.com/vpc/docs/vpc',
    recommended_action: 'Move resources from the default VPC to a new VPC created for that application or resource group.',
    apis: ['networks:list', 'instances:compute:list'],
    compliance: {
        pci: 'PCI has explicit requirements around default accounts and ' +
            'resources. PCI recommends removing all default accounts, ' +
            'only enabling necessary services as required for the function ' +
            'of the system'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.networks, function(region, rcb){
            let networks = helpers.addSource(
                cache, source, ['networks', 'list', region]);

            if (!networks) return rcb();

            if (networks.err || !networks.data) {
                helpers.addResult(results, 3, 'Unable to query networks: ' + helpers.addError(networks), region);
                return rcb();
            }

            if (!networks.data.length) {
                helpers.addResult(results, 0, 'No networks found', region);
                return rcb();
            }
            var defVPC = false;
            var vpcUrl = ''
            networks.data.forEach(network => {
               if (network.name == 'default') {
                    defVPC = true;
                    vpcUrl = network.selfLink;
               }
            });
            if (!defVPC)  {
                helpers.addResult(results, 0, 'No default VPC found', 'global');
                return rcb();
            }
            var numInstances = 0;

            async.each(regions.zones, function(location, icb){
                location.forEach(loc => {
                    let instances = helpers.addSource(cache, source,
                    ['instances', 'compute','list', loc]);

                    if (!instances || instances.err || !instances.data) {
                    } else if (instances.data.length) {
                        instances.data.forEach(instance => {
                            instance.networkInterfaces.forEach(interface => {
                                if (interface.network = vpcUrl) {
                                    numInstances += 1;
                                }
                            });
                        });
                    }
                }, function() {
                    icb();
                });
            });
            if (!numInstances) {
                helpers.addResult(results, 0, 'Default VPC is not in use', region);
                return rcb();
            } else {
                var numStr = numInstances + ' VM instance' + (numInstances === 1 ? '' : 's') + '; ';
                helpers.addResult(results, 2, 'Default VPC is in use: ' + numStr, region);
                return rcb();
            }

        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
