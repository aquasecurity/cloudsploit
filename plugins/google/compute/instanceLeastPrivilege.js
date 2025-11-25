var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'VM Instances Least Privilege',
    category: 'Compute',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that instances are not configured to use the default service account with full access to all cloud APIs',
    more_info: 'To support the principle of least privilege and prevent potential privilege escalation, it is recommended that instances are not assigned to the default service account, Compute Engine default service account with a scope allowing full access to all cloud APIs.',
    link: 'https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances',
    recommended_action: 'For all instances, if the default service account is used, ensure full access to all cloud APIs is not configured.',
    apis: ['compute:list', 'projects:getIamPolicy'],
    compliance: {
        pci: 'PCI has explicit requirements around default accounts and ' +
            'resources. PCI recommends removing all default accounts, ' +
            'only enabling necessary services as required for the function ' +
            'of the system'
    },
    realtime_triggers: ['compute.instances.insert', 'compute.instances.delete', 'compute.instances.setServiceAccount'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;
        var defaultServiceAccount = projects.data[0].defaultServiceAccount;

        var serviceAccountRoles = {};

        async.each(regions.projects, function (region, rcb) {
            let iamPolicy = helpers.addSource(cache, source,
                ['projects', 'getIamPolicy', region]);

            if (!iamPolicy) return rcb();

            if (iamPolicy.err || !iamPolicy.data || !iamPolicy.data.length) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM policies: ' + helpers.addError(iamPolicy), region);
                return rcb();
            }

            var iamPolicyData = iamPolicy.data[0];

            if (iamPolicyData && iamPolicyData.bindings && iamPolicyData.bindings.length) {
                iamPolicyData.bindings.forEach(roleBinding => {
                    if (!roleBinding.role || !roleBinding.members) return;

                    var role = roleBinding.role;

                    roleBinding.members.forEach(member => {
                        if (member.startsWith('serviceAccount:')) {
                            var serviceAccountEmail = member.split(':')[1];

                            if (!serviceAccountRoles[serviceAccountEmail]) {
                                serviceAccountRoles[serviceAccountEmail] = [];
                            }
                            serviceAccountRoles[serviceAccountEmail].push(role);
                        }
                    });
                });
            }

            rcb();
        }, function () {
            async.each(regions.compute, (computeRegion, computeRcb) => {
                var zones = regions.zones;
                var noInstances = [];

                async.each(zones[computeRegion], function (zone, zcb) {
                    var instances = helpers.addSource(cache, source,
                        ['compute', 'list', zone]);

                    if (!instances) return zcb();

                    if (instances.err || !instances.data) {
                        helpers.addResult(results, 3, 'Unable to query compute instances', computeRegion, null, null, instances.err);
                        return zcb();
                    }

                    if (!instances.data.length) {
                        noInstances.push(zone);
                        return zcb();
                    }

                    instances.data.forEach(instance => {
                        let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);

                        let instanceServiceAccountEmail = null;
                        let hasBroadRole = false;

                        if (instance.serviceAccounts && instance.serviceAccounts.length) {
                            instance.serviceAccounts.forEach(serviceAccount => {
                                if (serviceAccount.email) {
                                    instanceServiceAccountEmail = serviceAccount.email;
                                    var roles = serviceAccountRoles[serviceAccount.email] || [];
                                    var broadRoles = roles.filter(role =>
                                        role === 'roles/owner' ||
                                        role === 'roles/editor' ||
                                        role.endsWith('.admin')
                                    );
                                    if (broadRoles.length > 0) {
                                        hasBroadRole = true;
                                    }
                                }
                            });
                        }

                        if (hasBroadRole && instanceServiceAccountEmail) {
                            var roles = serviceAccountRoles[instanceServiceAccountEmail] || [];
                            var broadRoles = roles.filter(role =>
                                role === 'roles/owner' ||
                                role === 'roles/editor' ||
                                role.endsWith('.admin')
                            );
                            var roleStr = broadRoles.join(', ');
                            var isDefault = instanceServiceAccountEmail === defaultServiceAccount;
                            var serviceAccountType = isDefault ? 'default service account' : 'service account';
                            helpers.addResult(results, 2,
                                `Instance Service account has full access`, computeRegion, resource);
                        } else {
                            helpers.addResult(results, 0,
                                'Instance service account follows least privilege', computeRegion, resource);
                        }
                    });
                    return zcb();
                }, function () {
                    if (noInstances.length) {
                        helpers.addResult(results, 0, `No instances found in following zones: ${noInstances.join(', ')}`, computeRegion);
                    }
                    computeRcb();
                });
            }, function() {
                callback(null, results, source);
            });
        });
    }
};
