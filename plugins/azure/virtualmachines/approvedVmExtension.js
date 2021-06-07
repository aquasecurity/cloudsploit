var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Approved Extensions',
    category: 'Virtual Machines',
    description: 'Ensures that approved virtual machine extensions are installed.',
    more_info: 'Extensions are small applications that provide post-deployment configuration and automation on Azure VMs. Extensions installed should be approved by the organization to meet the organizational security requirements.',
    recommended_action: 'Uninstall unapproved virtual machine extensions',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/overview',
    apis: ['virtualMachines:listAll', 'virtualMachineExtensions:list'],
    settings: {
        vm_approved_extensions: {
            name: 'Approved VM extensions',
            description: 'List of comma separated approved extension names',
            regex: '^.*$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        const config = {
            approvedExtensions: settings.vm_approved_extensions || this.settings.vm_approved_extensions.default
        };

        if (!config.approvedExtensions.length) return callback(null, results, source);

        var extensionsList = config.approvedExtensions.split(',');

        async.each(locations.virtualMachines, function(location, rcb){
            var virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No Virtual Machines found', location);
                return rcb();
            }

            async.each(virtualMachines.data, function(virtualMachine, scb){
                const virtualMachineExtensions = helpers.addSource(cache, source,
                    ['virtualMachineExtensions', 'list', location, virtualMachine.id]);

                if (!virtualMachineExtensions || virtualMachineExtensions.err || !virtualMachineExtensions.data) {
                    helpers.addResult(results, 3, 'Unable to query for VM Extensions: ' + helpers.addError(virtualMachineExtensions), location, virtualMachine.id);
                    return scb();
                }
                
                if (!virtualMachineExtensions.data.length) {
                    helpers.addResult(results, 0, 'No VM Extensions found', location, virtualMachine.id);
                    return scb();
                }      
                
                virtualMachineExtensions.data.forEach(function(virtualMachineExtension) {
                    let found = extensionsList.some(extension => extension.trim() === virtualMachineExtension.name);

                    if (found) {
                        helpers.addResult(results, 0, 'Installed extensions are approved by the organization', location, virtualMachineExtension.id);
                    } else {
                        helpers.addResult(results, 2, 'Installed extensions are not approved by the organization', location, virtualMachineExtension.id);
                    }
                });
                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
