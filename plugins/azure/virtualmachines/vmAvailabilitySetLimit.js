var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Availability Set Limit',
    category: 'Virtual Machines',
    description: 'Determine if the number of VM instances is close to the Azure per-availability set limit',
    more_info: 'Azure limits availability sets to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/overview',
    recommended_action: 'Contact Azure support to increase the number of instances available',
    apis: ['resourceGroups:list', 'availabilitySets:listBySubscription'],
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
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            instance_limit_percentage_fail: settings.instance_limit_percentage_fail || 
                this.settings.instance_limit_percentage_fail.default,
            instance_limit_percentage_warn: settings.instance_limit_percentage_warn || 
                this.settings.instance_limit_percentage_warn.default
        };

        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.availabilitySets, function(location, rcb){

            var availabilitySets = helpers.addSource(cache, source, 
                ['availabilitySets', 'listBySubscription', location]);

            if (!availabilitySets) return rcb();

            if (availabilitySets.err || !availabilitySets.data) {
                helpers.addResult(results, 3, 
                    'Unable to query Availability Sets: ' + helpers.addError(availabilitySets), location);
                return rcb();
            }

            if (!availabilitySets.data.length) {
                helpers.addResult(results, 0, 'No existing Availability Sets', location);
                return rcb();
            }

            var limits = {
                'max-instances': 200
            };

            availabilitySets.data.forEach(availabilitySet => {
                if (availabilitySet.virtualMachines) {
                    var vmInstances = availabilitySet.virtualMachines.length;
                } else {
                    return;
                }

                var percentage = Math.ceil((vmInstances / limits['max-instances']) * 100);
                var returnMsg = 'Availability Set contains ' + vmInstances + ' of ' +
                    limits['max-instances'] + ' (' + percentage + '%) available instances';

                if (percentage >= config.instance_limit_percentage_fail) {
                    helpers.addResult(results, 2, returnMsg, location, availabilitySet.id);
                } else if (percentage >= config.instance_limit_percentage_warn) {
                    helpers.addResult(results, 1, returnMsg, location, availabilitySet.id);
                } else {
                    helpers.addResult(results, 0, returnMsg, location, availabilitySet.id);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};