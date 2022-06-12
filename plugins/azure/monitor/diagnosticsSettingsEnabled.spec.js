var expect = require('chai').expect;
var diagnosticsSettingsEnabled = require('./diagnosticsSettingsEnabled');

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

describe('diagnosticsSettingsEnabled', function() {
    describe('run', function() {
        it('should give failing result if no diagnostic settings found', function(done) {
            const cache = createCache([]);
            diagnosticsSettingsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Diagnostic Settings found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if diagnostic settings found', function(done) {
            const cache = createCache(diagnosticSettings);
            diagnosticsSettingsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Diagnostic Settings exist');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache();
            diagnosticsSettingsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Diagnostic Settings');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
