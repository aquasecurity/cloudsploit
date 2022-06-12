var expect = require('chai').expect;
var captureAppropriateCategories = require('./captureAppropriateCategories');

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
                'enabled': false
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

describe('captureAppropriateCategories', function() {
    describe('run', function() {
        it('should give failing result if no diagnostic settings found', function(done) {
            const cache = createCache([]);
            captureAppropriateCategories.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Diagnostic Settings found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache();
            captureAppropriateCategories.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Diagnostic Settings');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if logs are enabled for all appropriate categories', function(done) {
            const cache = createCache([diagnosticSettings[0]]);
            captureAppropriateCategories.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Logs for all appropriate categories are enabled for Diagnostic Settings');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if logs are not enabled for all appropriate categories', function(done) {
            const cache = createCache([diagnosticSettings[1]]);
            captureAppropriateCategories.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Logs for all appropriate categories are not enabled for Diagnostic Settings');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
