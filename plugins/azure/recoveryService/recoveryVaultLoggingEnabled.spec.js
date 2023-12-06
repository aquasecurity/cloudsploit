var expect = require('chai').expect;
var recoveryVaultLoggingEnabled = require('./recoveryVaultLoggingEnabled');

const listServiceVaults = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/77777777-b0c6-47a2-b37c-d8e65a629c18/resourceGroups/HelloWorld/providers/Microsoft.RecoveryServices/vaults/today1',
        'type': "Microsoft.RecoveryServices/vaults",
    }
];

const diagnosticSettings = [
    {
    id: '/subscriptions/77777777-b0c6-47a2-b37c-d8e65a629c18/resourceGroups/HelloWorld/providers/Microsoft.RecoveryServices/vaults/today1/providers/microsoft.insights/diagnosticSettings/gio-test-setting',
    type: 'Microsoft.Insights/diagnosticSettings',
    name: 'gio-test-setting',
    location: 'eastus',
    kind: null,
    tags: null,
    identity: null,
    storageAccountId: null,
    serviceBusRuleId: null,
    metrics: [],
    logs: [
      {
        category: 'RecoveryServiceVault',
        categoryGroup: null,
        enabled: true,
      },
      {
        category: 'RecoveryServiceVault',
        categoryGroup: null,
        enabled: true,
      }
    ],
    logAnalyticsDestinationType: null
    },
    {
    id: '/subscriptions/77777777-b0c6-47a2-b37c-d8e65a629c18/resourceGroups/HelloWorld/providers/Microsoft.RecoveryServices/vaults/today1/providers/microsoft.insights/diagnosticSettings/gio-test-setting',
    type: 'Microsoft.Insights/diagnosticSettings',
    name: 'gio-test-setting',
    location: 'eastus',
    kind: null,
    tags: null,
    identity: null,
    metrics: [],
    logs: [],
    logAnalyticsDestinationType: null
  },
];

const createCache = (listServiceVault, ds) => {
    const id = (listServiceVault && listServiceVault.length) ? listServiceVault[0].id : null;
    return {
        recoveryServiceVaults: {
            listBySubscriptionId: {
                'eastus': { data: listServiceVault }
            },
        },
        diagnosticSettings: {
          listByRecoveryServiceVault: {
                'eastus': { 
                    [id]: { 
                        data: ds 
                    }
                }
            }  
        }
    };
};

describe('recoveryVaultLoggingEnabled', function() {
    describe('run', function() {
        it('should give passing result if no Recovery Service vault found', function(done) {
            const cache = createCache([], null);
            recoveryVaultLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Recovery Service Vaults found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for list Recovery Service vault', function(done) {
            const cache = createCache(null, null);
            recoveryVaultLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list Recovery Service Vaults:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([listServiceVaults[0]], null);
            recoveryVaultLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Recovery Service Vault diagnostic settings: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if diagnostic logs enabled', function(done) {
            const cache = createCache([listServiceVaults[0]], [diagnosticSettings[0]]);
            recoveryVaultLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Recovery Service Vault has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if diagnostic logs not enabled', function(done) {
            const cache = createCache([listServiceVaults[0]], [diagnosticSettings[1]]);
            recoveryVaultLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Recovery Service Vault does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});