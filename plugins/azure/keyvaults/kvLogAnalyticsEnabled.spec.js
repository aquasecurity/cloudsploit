var expect = require('chai').expect;
var kvLogAnalyticsEnabled = require('./kvLogAnalyticsEnabled');

const vaults = [
    {
        id: '/subscriptions/1234/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-vault',
        name: 'test-vault',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus'
    }
];

const diagnosticSettings = [
    // PASS: destination + audit + allLogs both enabled
    {
        id: '/subscriptions/1234/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-vault/providers/microsoft.insights/diagnosticSettings/test',
        workspaceId: '/subscriptions/1234/resourceGroups/test-rg/providers/Microsoft.OperationalInsights/workspaces/test-law',
        storageAccountId: null,
        eventHubAuthorizationRuleId: null,
        logs: [
            { category: null, categoryGroup: 'audit', enabled: true },
            { category: null, categoryGroup: 'allLogs', enabled: true }
        ]
    },
    // FAIL: destination set but missing allLogs
    {
        id: '/subscriptions/1234/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-vault/providers/microsoft.insights/diagnosticSettings/test2',
        workspaceId: '/subscriptions/1234/resourceGroups/test-rg/providers/Microsoft.OperationalInsights/workspaces/test-law',
        storageAccountId: null,
        eventHubAuthorizationRuleId: null,
        logs: [
            { category: null, categoryGroup: 'audit', enabled: true }
        ]
    },
    // FAIL: no destination
    {
        id: '/subscriptions/1234/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-vault/providers/microsoft.insights/diagnosticSettings/test3',
        workspaceId: null,
        storageAccountId: null,
        eventHubAuthorizationRuleId: null,
        logs: [
            { category: null, categoryGroup: 'audit', enabled: true },
            { category: null, categoryGroup: 'allLogs', enabled: true }
        ]
    }
];

const createCache = (vault, diagnostics) => {
    let diagnostic = {};
    if (vault && vault.length) {
        diagnostic[vault[0].id] = { data: diagnostics };
    }
    return {
        vaults: {
            list: {
                'eastus': { data: vault }
            }
        },
        diagnosticSettings: {
            listByKeyVault: {
                'eastus': diagnostic
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key === 'vault') {
        return {
            vaults: { list: { 'eastus': {} } }
        };
    } else if (key === 'noVault') {
        return {
            vaults: { list: { 'eastus': { data: [] } } }
        };
    } else {
        return {
            vaults: { list: { 'eastus': { data: [vaults[0]] } } },
            diagnosticSettings: {
                listByKeyVault: { 'eastus': {} }
            }
        };
    }
};

describe('kvLogAnalyticsEnabled', function() {
    describe('run', function() {

        it('should give passing result if no Key Vaults found', function(done) {
            const cache = createErrorCache('noVault');
            kvLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Key Vaults', function(done) {
            const cache = createErrorCache('vault');
            kvLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query diagnostic settings', function(done) {
            const cache = createErrorCache('diagnostic');
            kvLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query diagnostics settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no diagnostic settings exist', function(done) {
            const cache = createCache([vaults[0]], []);
            kvLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing diagnostics settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no destination is configured', function(done) {
            const cache = createCache([vaults[0]], [diagnosticSettings[2]]);
            kvLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have a diagnostic logs destination configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if required category groups are missing', function(done) {
            const cache = createCache([vaults[0]], [diagnosticSettings[1]]);
            kvLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('missing required category groups');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Key Vault has diagnostic logs enabled with required category groups', function(done) {
            const cache = createCache([vaults[0]], [diagnosticSettings[0]]);
            kvLogAnalyticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key Vault has diagnostic logs enabled with required category groups');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
