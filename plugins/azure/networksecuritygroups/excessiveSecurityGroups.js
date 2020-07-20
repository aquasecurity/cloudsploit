const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Excessive Security Groups',
    category: 'Network Security Groups',
    description: 'Determines if there are an excessive number of security groups in the account',
    more_info: 'Keeping the number of security groups to a minimum helps reduce the attack surface of an account. Rather than creating new groups with the same rules for each project, common rules should be grouped under the same security groups. For example, instead of adding port 22 from a known IP to every group, create a single "SSH" security group which can be used on multiple instances.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/manage-network-security-group',
    recommended_action: 'Limit the number of security groups to prevent accidental authorizations.',
    apis: ['networkSecurityGroups:listAll'],
    settings: {
        excessive_security_groups_fail: {
            name: 'Excessive Security Groups Fail',
            description: 'Return a failing result when the number of security groups exceeds this value',
            regex: '^[1-9]{1}[0-9]{0,5}$',
            default: 40
        },
        excessive_security_groups_warn: {
            name: 'Excessive Security Groups Warn',
            description: 'Return a warning result when the number of security groups exceeds this value',
            regex: '^[1-9]{1}[0-9]{0,5}$',
            default: 30
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            excessive_security_groups_fail: settings.excessive_security_groups_fail || 
                this.settings.excessive_security_groups_fail.default,
            excessive_security_groups_warn: settings.excessive_security_groups_warn || 
                this.settings.excessive_security_groups_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.networkSecurityGroups, function(location, rcb) {

            let networkSecurityGroups = helpers.addSource(cache, source, 
                ['networkSecurityGroups', 'listAll', location]);

            if (!networkSecurityGroups) return rcb();

            if (networkSecurityGroups.err || !networkSecurityGroups.data) {
                helpers.addResult(results, 3, 
                    'Unable to query for Network Security Groups: ' + helpers.addError(networkSecurityGroups), location);
                return rcb();
            }

            if (!networkSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups found', location);
                return rcb();
            }

            var returnMsg = ' number of security groups: ' + 
                networkSecurityGroups.data.length + ' groups present';

            if (networkSecurityGroups.data.length > config.excessive_security_groups_fail) {
                helpers.addResult(results, 2, 'Excessive' + returnMsg, location, null, custom);
            } else if (networkSecurityGroups.data.length > config.excessive_security_groups_warn) {
                helpers.addResult(results, 1, 'Large' + returnMsg, location, null, custom);
            } else {
                helpers.addResult(results, 0, 'Acceptable' + returnMsg, location, null, custom);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};