var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Excessive Firewall Rules',
    category: 'VPC Network',
    description: 'Determines if there are an excessive number of firewall rules in the account',
    more_info: 'Keeping the number of firewall rules to a minimum helps reduce the attack surface of an account. Rather than creating new rules with the same rules for each project, common rules should be grouped under the same firewall rule. For example, instead of adding port 22 from a known IP to every firewall rule, create a single "SSH" firewall rule which can be used on multiple instances.',
    link: 'https://cloud.google.com/vpc/docs/using-firewalls',
    recommended_action: 'Limit the number of firewall rules to prevent accidental authorizations',
    apis: ['firewalls:list'],
    compliance: {
        pci: 'PCI has strict requirements to segment networks using firewalls. ' +
             'Firewall Rules are a software-layer firewall that should be used ' +
             'to isolate resources. Ensure the number of groups does not become ' +
             'unmanageable.'
    },
    settings: {
        excessive_firewall_rules_fail: {
            name: 'Excessive Firewall Rules Fail',
            description: 'Return a failing result when the number of Firewall Rules exceeds this value',
            regex: '^[1-9]{1}[0-9]{0,5}$',
            default: 40
        },
        excessive_firewall_rules_warn: {
            name: 'Excessive Firewall Rules Warn',
            description: 'Return a warning result when the number of Firewall Rules exceeds this value',
            regex: '^[1-9]{1}[0-9]{0,5}$',
            default: 30
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            excessive_firewall_rules_fail: settings.excessive_firewall_rules_fail || this.settings.excessive_firewall_rules_fail.default,
            excessive_firewall_rules_warn: settings.excessive_firewall_rules_warn || this.settings.excessive_firewall_rules_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.firewalls, function(region, rcb){
            let firewalls = helpers.addSource(
                cache, source, ['firewalls', 'list', region]);

            if (!firewalls) return rcb();

            if (firewalls.err || !firewalls.data) {
                helpers.addResult(results, 3, 'Unable to query firewall rules: ' + helpers.addError(firewalls), region);
                return rcb();
            }

            if (!firewalls.data.length) {
                helpers.addResult(results, 0, 'No firewall rules found', region);
                return rcb();
            }

            var returnMsg = ' number of firewall rules: ' + firewalls.data.length + ' rules present';

            if (firewalls.data.length > config.excessive_firewall_rules_fail) {
                helpers.addResult(results, 2, 'Excessive' + returnMsg, region, null, custom);
            } else if (firewalls.data.length > config.excessive_firewall_rules_warn) {
                helpers.addResult(results, 1, 'Large' + returnMsg, region, null, custom);
            } else {
                helpers.addResult(results, 0, 'Acceptable' + returnMsg, region, null, custom);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}