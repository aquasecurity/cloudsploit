var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Instance Limit',
    category: 'Virtual Machines',
    description: 'Determines if the number of VM instances is close to the Azure per-region limit',
    more_info: 'Azure limits regions to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/overview',
    recommended_action: 'Contact Azure support to increase the number of instances available',
    apis: ['virtualMachines:listAll'],
    settings: {
        instance_limit_percentage_fail: {
            name: 'Instance Limit Percentage Fail',
            description: 'Return a failing result when utilized instances equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 90
        },
        instance_limit_percentage_warn: {
            name: 'Instance Limit Percentage Warn',
            description: 'Return a warning result when utilized instances equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 75
        },
        instance_limit: {
            name: 'Instance Limit',
            description: 'The amount of allowed instances per region.',
            regex: '^(100|[1-9][0-9]?)$',
            default: 25000
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            instance_limit_percentage_fail: settings.instance_limit_percentage_fail || 
                this.settings.instance_limit_percentage_fail.default,
            instance_limit_percentage_warn: settings.instance_limit_percentage_warn || 
                this.settings.instance_limit_percentage_warn.default,
            instance_limit: settings.instance_limit || 
                this.settings.instance_limit.default
        };

        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb){

            var virtualMachines = helpers.addSource(cache, source, 
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 
                    'Unable to query Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines', location);
                return rcb();
            }

            var vmInstances = virtualMachines.data.length;

            var percentage = Math.ceil((vmInstances / config.instance_limit) * 100);
            var returnMsg = 'Region contains ' + vmInstances + ' of ' +
                config.instance_limit + ' (' + percentage + '%) available instances';

            if (percentage >= config.instance_limit_percentage_fail) {
                helpers.addResult(results, 2, returnMsg, location);
            } else if (percentage >= config.instance_limit_percentage_warn) {
                helpers.addResult(results, 1, returnMsg, location);
            } else {
                helpers.addResult(results, 0, returnMsg, location);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};