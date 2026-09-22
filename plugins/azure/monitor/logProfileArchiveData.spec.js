var expect = require('chai').expect;
var logProfileArchiveData = require('./logProfileArchiveData');

const diagnosticSettings = [
    {
        'id': '/subscriptions/123/providers/microsoft.insights/diagnosticSettings/test-setting',
        'type': 'Microsoft.Insights/diagnosticSettings',
        'name': 'test-setting',
        'location': 'global',
        'storageAccountId': '/subscriptions/123/resourceGroups/devresourcegroup/providers/Microsoft.Storage/storageAccounts/test-storage-account',
        'logs': [
            { 'category': 'Administrative', 'enabled': true },
            { 'category': 'Security', 'enabled': true }
        ]
    },
    {
        'id': '/subscriptions/123/providers/microsoft.insights/diagnosticSettings/test-setting-eventhub',
        'type': 'Microsoft.Insights/diagnosticSettings',
        'name': 'test-setting-eventhub',
        'location': 'global',
        'eventHubAuthorizationRuleId': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.EventHub/namespaces/test-setting/authorizationrules/RootManageSharedAccessKey',
        'eventHubName': '',
        'logs': [
            { 'category': 'Administrative', 'enabled': true },
            { 'category': 'Security', 'enabled': true }
        ]
    },
    {
        'id': '/subscriptions/123/providers/microsoft.insights/diagnosticSettings/test-setting-disabled',
        'type': 'Microsoft.Insights/diagnosticSettings',
        'name': 'test-setting-disabled',
        'location': 'global',
        'storageAccountId': '/subscriptions/123/resourceGroups/devresourcegroup/providers/Microsoft.Storage/storageAccounts/test-storage-account',
        'logs': [
            { 'category': 'Administrative', 'enabled': false },
            { 'category': 'Security', 'enabled': false }
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

describe('logProfileArchiveData', function() {
    describe('run', function() {
        it('should give failing result if no diagnostic settings found', function(done) {
            const cache = createCache([]);
            logProfileArchiveData.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Diagnostic Settings found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache();
            logProfileArchiveData.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Diagnostic Settings');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if a diagnostic setting archives activity logs to a storage account', function(done) {
            const cache = createCache([diagnosticSettings[0]]);
            logProfileArchiveData.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Diagnostic Setting is archiving Activity Logs to a storage account');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if no diagnostic setting archives activity logs to a storage account', function(done) {
            const cache = createCache([diagnosticSettings[1]]);
            logProfileArchiveData.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No Diagnostic Setting is archiving Activity Logs to a storage account');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if diagnostic setting has a storage account but no enabled logs', function(done) {
            const cache = createCache([diagnosticSettings[2]]);
            logProfileArchiveData.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No Diagnostic Setting is archiving Activity Logs to a storage account');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
