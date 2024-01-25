var expect = require('chai').expect;
var autoscaleNotificationsEnabled = require('./autoscaleNotificationsEnabled');

const virtualMachineScaleSets = [
    {
        'name': 'test-ali-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'location': 'eastus'
    }
];

const autoScaleSettings = [
    {
        'id': '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/aqua-resource-group/providers/microsoft.insights/autoscalesettings/test-vmss-Autoscale',
        'targetResourceUri': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'name': 'test-vmss-Autoscale',
        'type': 'Microsoft.Insights/autoscaleSettings',
        'notifications': [
            {
                'operation': 'Scale',
                'email': {
                    'sendToSubscriptionAdministrator': true,
                    'sendToSubscriptionCoAdministrators': false,
                    'customEmails': []
                },
                'webhooks': []
            }
        ]
    },
    {
        'id': '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/aqua-resource-group/providers/microsoft.insights/autoscalesettings/test-vmss-Autoscale',
        'targetResourceUri': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'name': 'test-vmss-Autoscale',
        'type': 'Microsoft.Insights/autoscaleSettings',
        'notifications': [
            {
                'operation': 'Scale',
                'email': {
                    'sendToSubscriptionAdministrator': false,
                    'sendToSubscriptionCoAdministrators': true,
                    'customEmails': []
                },
                'webhooks': []
            }
        ]
    },
    {
        'id': '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/aqua-resource-group/providers/microsoft.insights/autoscalesettings/test-vmss-Autoscale',
        'targetResourceUri': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'name': 'test-vmss-Autoscale',
        'type': 'Microsoft.Insights/autoscaleSettings',
        'notifications': [
            {
                'operation': 'Scale',
                'email': {
                    'sendToSubscriptionAdministrator': false,
                    'sendToSubscriptionCoAdministrators': false,
                    'customEmails': ['testemail@test.com']
                },
                'webhooks': []
            }
        ]
    },
    {
        'id': '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/aqua-resource-group/providers/microsoft.insights/autoscalesettings/test-vmss-Autoscale',
        'targetResourceUri': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'name': 'test-vmss-Autoscale',
        'type': 'Microsoft.Insights/autoscaleSettings',
        'notifications': [
            {
                'operation': 'Scale',
                'email': {
                    'sendToSubscriptionAdministrator': false,
                    'sendToSubscriptionCoAdministrators': false,
                    'customEmails': []
                },
                'webhooks': ['http://webhookendpoint.com/webhook']
            }
        ]
    },
    {
        'id': '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/aqua-resource-group/providers/microsoft.insights/autoscalesettings/test-vmss-Autoscale',
        'targetResourceUri': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'name': 'test-vmss-Autoscale',
        'type': 'Microsoft.Insights/autoscaleSettings',
        'notifications': [
            {
                'operation': 'Scale',
                'email': {
                    'sendToSubscriptionAdministrator': false,
                    'sendToSubscriptionCoAdministrators': false,
                    'customEmails': []
                },
                'webhooks': []
            }
        ]
    },
];

const createCache = (virtualMachineScaleSets, autoscaleSettings) => {
    let scaleSet = {};
    let autoScaleSetting = {};
    if (virtualMachineScaleSets) {
        scaleSet['data'] = virtualMachineScaleSets;
    }
    if (autoscaleSettings) {
        autoScaleSetting['data'] = autoscaleSettings;
    }
    return {
        virtualMachineScaleSets: {
            listAll: {
                'eastus': scaleSet
            }
        },
        autoscaleSettings: {
            listBySubscription: {
                'eastus': autoScaleSetting
            }
        }
    };
};

describe('autoscaleNotificationsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machine scale sets', function(done) {
            const cache = createCache([]);
            autoscaleNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
            const cache = createCache(null);
            autoscaleNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no autoscale settings', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]], []);
            autoscaleNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No Virtual Machine Scale Sets have autoscale enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for autoscale settings', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]]);
            autoscaleNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for AutoScale settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no autoscale email to admins enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]], [autoScaleSettings[0]]);
            autoscaleNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine Scale Set has autoscale notifications enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no autoscale email to co-admins enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]], [autoScaleSettings[1]]);
            autoscaleNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine Scale Set has autoscale notifications enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no autoscale email to custom emails enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]], [autoScaleSettings[2]]);
            autoscaleNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine Scale Set has autoscale notifications enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no autoscale email to admins enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]], [autoScaleSettings[3]]);
            autoscaleNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine Scale Set has autoscale notifications enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no autoscale notifications are disabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]], [autoScaleSettings[4]]);
            autoscaleNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Machine Scale Set has autoscale notifications disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});