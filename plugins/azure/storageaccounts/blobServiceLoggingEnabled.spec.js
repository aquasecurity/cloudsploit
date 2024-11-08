var expect = require('chai').expect;
var blobServiceLoggingEnabled = require('./blobServiceLoggingEnabled');

const storageAccounts = [
    {
        kind: 'StorageV2',
        id: '/subscriptions/1234/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Storage/storageAccounts/csb100320011e293683',
        name: 'csb100320011e293683',
        type: 'Microsoft.Storage/storageAccounts',
        location: 'eastus',
    },
    {
        kind: 'StorageV2',
        id: '/subscriptions/1234/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Storage/storageAccounts/csb100320011e293683',
        name: 'csb100320011e293683',
        type: 'Microsoft.Storage/storageAccounts',
        location: 'eastus',
        sku: {
            tier: 'Premium'
        }
    }
];

const diagnosticSettings = [
    {
        id: "/subscriptions/1234/resourcegroups/test/providers/microsoft.storage/storageaccounts/test1/blobservices/default/providers/microsoft.insights/diagnosticSettings/testsetting",
        type: "Microsoft.Insights/diagnosticSettings",
        name: "testsetting",
        location: "eastus",
        logs: [
            {
                category: "StorageRead",
                categoryGroup: null,
                enabled: true,
                retentionPolicy: {
                    enabled: false,
                    days: 0,
                },
            },
            {
                category: "StorageWrite",
                categoryGroup: null,
                enabled: true,
                retentionPolicy: {
                    enabled: false,
                    days: 0,
                },
            },
            {
                category: "StorageDelete",
                categoryGroup: null,
                enabled: true,
                retentionPolicy: {
                    enabled: false,
                    days: 0,
                },
            },
        ],
        logAnalyticsDestinationType: null,
    },
    {
        id: "/subscriptions/1234/resourcegroups/test/providers/microsoft.storage/storageaccounts/test1/blobservices/default/providers/microsoft.insights/diagnosticSettings/testsetting",
        type: "Microsoft.Insights/diagnosticSettings",
        name: "testsetting",
        location: "eastus",
        logs: [
        ],
        logAnalyticsDestinationType: null,
    },
];
const createCache = (storageAccounts, diagnosticSettings) => {
    let diagnostic = {};
    if (storageAccounts.length) {
        diagnostic[storageAccounts[0].id] = {
            data: diagnosticSettings
        };
    }
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    data: storageAccounts
                }
            }
        },
        diagnosticSettings: {
            listByBlobServices: {
                'eastus': diagnostic
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key == 'storageAccounts') {
        return {
            storageAccounts: {
                list: {
                    'eastus': {}
                }
            }
        };
    } else if (key === 'noStorageAccount'){
        return {
            storageAccounts: {
                list: {
                    'eastus': {
                        data:{}
                    }
                }
            }
        };
    }else if (key === 'diagnostic') {
        return {
            storageAccounts: {
                list: {
                    'eastus': {
                        data: [storageAccounts[0]]
                    }
                }
            },
            diagnosticSettings: {
                diagnosticSettings: {
                    'eastus': {}
                }
            }
        };
    } else {
        const appId = (storageAccounts && storageAccounts.length) ? storageAccounts[0].id : null;
        const diagnosticSetting = (diagnosticSettings && diagnosticSettings.length) ? diagnosticSettings[0].id : null;
        return {
            storageAccounts: {
                list: {
                    'eastus': {
                        data: [appId[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByBlobServices: {
                    'eastus': {
                        data: {}
                    }
                }
            }
        };
    }
};

describe('blobServiceLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if Blob Service has logging enabled', function (done) {
            const cache = createCache([storageAccounts[0]],[diagnosticSettings[0]]);
            blobServiceLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('Storage Account has logging enabled for blob service read, write and delete requests');
                done();
            });
        });

        it('should Fail if Blob Service does not have logging enabled', function (done) {
            const cache = createCache([storageAccounts[0]],[diagnosticSettings[1]]);
            blobServiceLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.equal('Storage Account does not have logging enabled for blob service. Missing Logs StorageRead,StorageWrite,StorageDelete');
                done();
            });
        });

        it('should PASS if no storage account found', function (done) {
            const cache = createCache([], []);
            blobServiceLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('eastus');
                expect(results[0].message).to.equal('No storage accounts found');

                done();
            });
        });

        it('should PASS if storage account tier is premium', function (done) {
            const cache = createCache([storageAccounts[1]], []);
            blobServiceLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('eastus');
                expect(results[0].message).to.equal('Storage Account tier is premium');

                done();
            });
        });

        it('should UNKNOWN if Unable to query for for storage accounts', function (done) {
            const cache = createErrorCache('diagnostic');
            blobServiceLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Storage Account diagnostics settings: Unable to obtain data');
                done();
            });
        });
    });
});
