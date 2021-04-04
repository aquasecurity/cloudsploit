var expect = require('chai').expect;
var logStorageEncryption = require('./logStorageEncryption');

const diagnosticSettings = [
    {
        'id': 'subscriptions/123/providers/microsoft.insights/diagnosticSettings/test_log_1',
        'type': 'Microsoft.Insights/diagnosticSettings',
        'name': 'test_log_1',
        'location': 'global'
    }
];

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/test-storage',
        'name': 'test-storage',
        'encryption': {
            'keySource': 'Microsoft.Keyvault'
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/test-storage',
        'name': 'test-storage',
        'encryption': {
            'keySource': 'Microsoft.Storage'
        }
    }
];

const blobContainers = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/test-storage/blobServices/default/containers/insights-operational-logs',
        'name': 'insights-operational-logs',
        'publicAccess': 'None'
    }
];

const createCache = (diagnosticSettingsOperations, storageAccounts, blobContainers) => {
    let containers = {};
    if (storageAccounts.length > 0) {
        containers[storageAccounts[0].id] = {
            data: blobContainers
        };
    }
    return {
        diagnosticSettingsOperations: {
            list: {
                'global': {
                    data: diagnosticSettingsOperations
                }
            }
        },
        storageAccounts: {
            list: {
                'eastus': {
                    data: storageAccounts
                }
            }
        },
        blobContainers: {
            list: {
                'eastus': containers
            }
        }
    };
};

const createDiagnostingSettingsErrorCache = () => {
    return {
        diagnosticSettingsOperations: {
            list: {
                'global': {}
            }
        }
    };
};

const createStorageAccountsErrorCache = () => {
    return {
        diagnosticSettingsOperations: {
            list: {
                'global': {
                    data: [diagnosticSettings[0]]
                }
            }
        },
        storageAccounts: {
            list: {
                'eastus': {}
            }
        }
    };
};

const createBlobContainersErrorCache = () => {
    return {
        diagnosticSettingsOperations: {
            list: {
                'global': {
                    data: [diagnosticSettings[0]]
                }
            }
        },
        storageAccounts: {
            list: {
                'eastus': {
                    data: [storageAccounts[0]]
                }
            }
        },
        blobContainers: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('logStorageEncryption', function() {
    describe('run', function() {
        it('should give passing result if no diagnostic settings found', function(done) {
            const cache = createCache([], [], []);
            logStorageEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No diagnostic settings found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createDiagnostingSettingsErrorCache();
            logStorageEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for diagnostic settings:');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if no storage accounts found', function(done) {
            const cache = createCache([diagnosticSettings[0]], [], []);
            logStorageEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createStorageAccountsErrorCache();
            logStorageEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for blob containers', function(done) {
            const cache = createBlobContainersErrorCache();
            logStorageEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);

                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage containers:');

                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('No existing Storage Containers found for insight logs');

                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no existing Storage Containers found for insight logs', function(done) {
            const cache = createCache([diagnosticSettings[0]], [storageAccounts[0]], []);
            logStorageEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Storage Containers found for insight logs');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if activity logs container for the storage account is encrypted with BYOK', function(done) {
            const cache = createCache([diagnosticSettings[0]], [storageAccounts[0]], [blobContainers[0]]);
            logStorageEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Activity Logs container for the storage account is encrypted with BYOK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if activity logs container for the storage account is not encrypted with BYOK', function(done) {
            const cache = createCache([diagnosticSettings[0]], [storageAccounts[1]], [blobContainers[0]]);
            logStorageEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Activity Logs container for the storage account is not encrypted with BYOK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 