var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Desired SKU Size',
    category: 'Virtual Machines',
    description: 'Ensures that virtual machines is using the desired SKU size. This is an opt in plugin and will not run if no desired SKU size is provided.',
    more_info: 'VM SKU size defines the compute power and data processing speed. VM SKU size should be chosen carefully to address compute requirements for the organization and to save un-necessary costs.',
    recommended_action: 'Resize VM to desired SKU size.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/sizes',
    apis: ['virtualMachines:listAll'],
    settings: {
        vm_desired_sku_size: {
            name: 'VM Desired SKU Size',
            description: 'Comma separated desired SKU sizes for the virtual machines. Created virtual machine SKU sizes should match the desired SKU size.Please visit https://docs.microsoft.com/en-us/azure/virtual-machines/sizes for available sizes',
            regex: '(.*,?)+',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        const config = {
            desiredSkuSize: settings.vm_desired_sku_size || this.settings.vm_desired_sku_size.default
        };

        if (!config.desiredSkuSize.length) {
            return callback(null, results, source);
        }

        async.each(locations.virtualMachines, function(location, rcb) {
            const virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machines : ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing virtual machines', location);
                return rcb();
            }

            async.each(virtualMachines.data, function(virtualMachine, scb) {
                let vmSkuSize;
                if (virtualMachine.hardwareProfile && virtualMachine.hardwareProfile.vmSize) {
                    vmSkuSize = virtualMachine.hardwareProfile.vmSize.toLowerCase();
                } else {
                    return scb();
                }

                if ((config.desiredSkuSize.toLowerCase()).includes(vmSkuSize)) {
                    helpers.addResult(results, 0, `Virtual machine is using the desired SKU size of '${config.desiredSkuSize.toLowerCase()}'`, location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, `Virtual machine is not using the desired SKU size of '${config.desiredSkuSize.toLowerCase()}'`, location, virtualMachine.id);
                }

                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};