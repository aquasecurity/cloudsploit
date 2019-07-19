var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Excessive Security Groups',
    category: 'EC2',
    description: 'Determine if there are an excessive number of security groups in the account',
    more_info: 'Keeping the number of security groups to a minimum helps reduce the attack surface of an account. Rather than creating new groups with the same rules for each project, common rules should be grouped under the same security groups. For example, instead of adding port 22 from a known IP to every group, create a single "SSH" security group which can be used on multiple instances.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Limit the number of security groups to prevent accidental authorizations',
    apis: ['EC2:describeSecurityGroups'],
    compliance: {
        pci: 'PCI has strict requirements to segment networks using firewalls. ' +
             'Security groups are a software-layer firewall that should be used ' +
             'to isolate resources. Ensure the number of groups does not become ' +
             'unmanageable.'
    },
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
            excessive_security_groups_fail: settings.excessive_security_groups_fail || this.settings.excessive_security_groups_fail.default,
            excessive_security_groups_warn: settings.excessive_security_groups_warn || this.settings.excessive_security_groups_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){

            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);
            
            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups present', region);
                return rcb();
            }

            var returnMsg = ' number of security groups: ' + describeSecurityGroups.data.length + ' groups present';

            if (describeSecurityGroups.data.length > config.excessive_security_groups_fail) {
                helpers.addResult(results, 2, 'Excessive' + returnMsg, region, null, custom);
            } else if (describeSecurityGroups.data.length > config.excessive_security_groups_warn) {
                helpers.addResult(results, 1, 'Large' + returnMsg, region, null, custom);
            } else {
                helpers.addResult(results, 0, 'Acceptable' + returnMsg, region, null, custom);
            }

            rcb();
            
        }, function(){
            callback(null, results, source);
        });
    }
};
