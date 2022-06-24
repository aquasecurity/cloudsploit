var expect = require('chai').expect;
var monitorLogsEnabled = require('./monitorLogsEnabled');

const diagnosticSettings = [
    {
        'id': 'subscriptions/123/providers/microsoft.insights/diagnosticSettings/test-setting',
        'type': 'Microsoft.Insights/diagnosticSettings',
        'name': 'test-setting',
        'location': 'global',
        'storageAccountId': '/subscriptions/123/resourceGroups/devresourcegroup/providers/Microsoft.Storage/storageAccounts/test-storage-account',
        'logs': [
            {
                'category': 'Administrative',
                'enabled': true
            },
            {
                'category': 'Security',
                'enabled': true
            },
            {
                'category': 'ServiceHealth',
                'enabled': true
            },
            {
                'category': 'Alert',
                'enabled': true
            },
            {
                'category': 'Recommendation',
                'enabled': true
            },
            {
                'category': 'Policy',
                'enabled': true
            },
            {
                'category': 'Autoscale',
                'enabled': true
            },
            {
                'category': 'ResourceHealth',
                'enabled': true
            }
        ]
    },
    {
        'id': 'subscriptions/123/providers/microsoft.insights/diagnosticSettings/test-setting',
        'type': 'Microsoft.Insights/diagnosticSettings',
        'name': 'test-setting',
        'location': 'global',
        'storageAccountId': '/subscriptions/123/resourceGroups/devresourcegroup/providers/Microsoft.Storage/storageAccounts/test-storage-account',
        'logs': [
            {
                'category': 'Administrative',
                'enabled': true
            },
            {
                'category': 'Security',
                'enabled': true
            },
            {
                'category': 'ServiceHealth',
                'enabled': true
            },
            {
                'category': 'Alert',
                'enabled': true
            },
            {
                'category': 'Recommendation',
                'enabled': true
            },
            {
                'category': 'Policy',
                'enabled': true
            },
            {
                'category': 'Autoscale',
                'enabled': true
            },
            {
                'category': 'ResourceHealth',
                'enabled': false
            }
        ]
    },
    {
        'id': 'subscriptions/123/providers/microsoft.insights/diagnosticSettings/test-setting',
        'type': 'Microsoft.Insights/diagnosticSettings',
        'name': 'test-setting',
        'location': 'global',
        'eventHubAuthorizationRuleId': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.EventHub/namespaces/test-setting/authorizationrules/RootManageSharedAccessKey',
        'eventHubName': '',
        'logs': [
            {
                'category': 'Administrative',
                'enabled': true
            },
            {
                'category': 'Security',
                'enabled': true
            },
            {
                'category': 'ServiceHealth',
                'enabled': true
            },
            {
                'category': 'Alert',
                'enabled': true
            },
            {
                'category': 'Recommendation',
                'enabled': true
            },
            {
                'category': 'Policy',
                'enabled': true
            },
            {
                'category': 'Autoscale',
                'enabled': true
            },
            {
                'category': 'ResourceHealth',
                'enabled': true
            }
        ]
    }
];

const createCache = (diagnosticSettings) => {
    let settings = {};
    if (diagnosticSettings) {
        settings['data'] = diagnosticSettings;
    }
    return {
        diagnosticSettingsOperations: {
            list: {
                'global': settings
            }
        }
    };
};

describe('monitorLogsEnabled', function() {
    describe('run', function() {
        it('should give failing result if no diagnostic settings found', function(done) {
            const cache = createCache([]);
            monitorLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Diagnostic Settings found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache();
            monitorLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Diagnostic Settings');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if logs are enabled for all logging categories and storage account configured', function(done) {
            const cache = createCache([diagnosticSettings[0]]);
            monitorLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Diagnostic Setting has Azure Monitor Logs enabled for all the logging categories and Storage Account configured');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if logs are not enabled for all logging categories and storage account configured', function(done) {
            const cache = createCache([diagnosticSettings[1]]);
            monitorLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Diagnostic Setting does not have Azure Monitor Logs enabled for all the logging categories');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if logs are enabled for all logging categories and storage account is not configured', function(done) {
            const cache = createCache([diagnosticSettings[2]]);
            monitorLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Diagnostic Setting does not have a Storage Account configured for Azure Monitor Logs');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});