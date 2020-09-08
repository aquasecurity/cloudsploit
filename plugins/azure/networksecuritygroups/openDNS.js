const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Open DNS',
    category: 'Network Security Groups',
    description: 'Determine if TCP or UDP port 53 for DNS is open to the public',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as DNS should be restricted to known IP addresses.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/manage-network-security-group',
    recommended_action: 'Restrict TCP and UDP port 53 to known IP addresses',
    apis: ['networkSecurityGroups:listAll'],
    remediation_min_version: '202008121825',
    remediation_description: 'The impacted network security group rule will be deleted if no input is provided. If the failing port is in a port range and no input is provided, the range will be deleted. Otherwise, any input will replace the open CIDR rule.',
    apis_remediate: ['networkSecurityGroups:listAll'],
    actions: {remediate:['networkSecurityGroups:update'], rollback:['networkSecurityGroups:update']},
    permissions: {remediate: ['networkSecurityGroups:update'], rollback: ['networkSecurityGroups:update']},

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.networkSecurityGroups, function(location, rcb) {

            let networkSecurityGroups = helpers.addSource(cache, source,
                ['networkSecurityGroups', 'listAll', location]);

            if (!networkSecurityGroups) return rcb();

            if (networkSecurityGroups.err || !networkSecurityGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for Network Security Groups: ' + helpers.addError(networkSecurityGroups), location);
                return rcb();
            }

            if (!networkSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups found', location);
                return rcb();
            }

            let ports = {
                'UDP': [53],
                'TCP': [53]
            };

            let service = 'DNS';

            helpers.findOpenPorts(networkSecurityGroups.data, ports, service, location, results);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;

        // inputs specific to the plugin
        var pluginName = 'openDNS';
        var baseUrl = 'https://management.azure.com/{resource}?api-version=2020-05-01';
        var method = 'PUT';
        var protocols = ['TCP','UDP','*'];
        var port = 53;
        var errors = [];
        var actions = [];

        // create the params necessary for the remediation
        async.each(protocols,function(protocol, cb) {
            helpers.remediateOpenPorts(putCall, pluginName, protocol, port, config, cache, settings, resource, remediation_file, baseUrl, method,function(error, action) {
                if (error && (error.length || Object.keys(error).length)) {
                    errors.push(error);
                } else if (action && (action.length || Object.keys(action).length)){
                    actions.push(action);
                }

                cb();
            });
        }, function() {
            if (errors && errors.length) {
                remediation_file['post_remediate']['actions'][pluginName]['error'] = errors.join(', ');
                settings.remediation_file = remediation_file;
                return callback(errors, null);
            } else {
                remediation_file['post_remediate']['actions'][pluginName][resource] = actions;
                settings.remediation_file = remediation_file;
                return callback(null, actions);
            }
        });
    }
};