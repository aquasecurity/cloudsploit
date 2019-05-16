const async = require('async');

const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Disk Encryption',
    category: 'Security Center',
    description: 'Ensures Disk Encryption monitoring is enabled in Security Center.',
    more_info: 'When this setting is enabled, Security Center audits disk encryption in all virtual machines (Windows and Linux as well) to enhance data protection at rest.',
    recommended_action: '1. Go to Azure Security Center 2. Click On the security policy to Open Policy Management Blade. 3. Click Subscription View 4. Click on Subscription Name to open Security Policy Blade for the Subscription. 5. Expand Compute And Apps 6. Ensure that Disk Encryption is not set to Disabled',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list','disks:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, (location, rcb) => {

            const policyAssignments = helpers.addSource(
                cache, source, ['policyAssignments', 'list', location]
            );

            var disksList = helpers.addSource(cache, source, ['disks', 'list', location]);

            if(disksList &&
                disksList.data &&
                disksList.data.length>0) {
                if (!policyAssignments || policyAssignments.err || !policyAssignments.data) {
                    helpers.addResult(
                        results,
                        3,
                        'Unable to query PolicyAssignments: ' + helpers.addError(policyAssignments),
                        location
                    );
                    return rcb();
                }

                if (!policyAssignments.data.length) {
                    helpers.addResult(
                        results,
                        0,
                        'No existing Security Policies'
                        , location
                    );
                    return rcb();
                }

                for (let res in policyAssignments.data) {
                    let isPolicyDisabled = false;
                    let isPolicyDefaultFound = false;

                    const policyAssignment = policyAssignments.data[res];

                    if (policyAssignment !== undefined) {
                        if (policyAssignment.displayName.indexOf("ASC Default") > -1) {
                            isPolicyDefaultFound = true
                            if (policyAssignment.parameters !== undefined &&
                                policyAssignment.parameters.diskEncryptionMonitoringEffect !== undefined &&
                                policyAssignment.parameters.diskEncryptionMonitoringEffect.value == 'Disabled') {
                                isPolicyDisabled = true;
                            }
                        } else if (policyAssignment.displayName.indexOf("Monitor unencrypted VM Disks in Azure Security Center") > -1) {
                            isPolicyDefaultFound = false
                            if (policyAssignment.parameters !== undefined &&
                                policyAssignment.parameters.effect !== undefined &&
                                policyAssignment.parameters.effect.value == 'Disabled') {
                                isPolicyDisabled = true;
                            }
                        } else {
                            continue;
                        }

                        if (!isPolicyDisabled) {
                            helpers.addResult(
                                results,
                                0,
                                'Disk Encryption Security Policy is Enabled in the policy: ' + policyAssignment.displayName,
                                location
                            );
                        } else {
                            helpers.addResult(
                                results,
                                2,
                                'Disk Encryption Security Policy is Disabled in the policy: ' + policyAssignment.displayName,
                                location
                            );
                        }
                    }
                }
            } else {
                helpers.addResult(
                    results,
                    0,
                    'No matching resources found, ignoring monitoring requirement',
                    location
                );
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};