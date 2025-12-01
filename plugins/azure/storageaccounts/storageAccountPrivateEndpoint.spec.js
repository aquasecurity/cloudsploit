var expect = require('chai').expect;
var storageAccountPrivateEndpoint = require('./storageAccountPrivateEndpoint');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc1',
        'location': 'eastus',
        'name': 'acc1',
        'tags': { 'key': 'value' },
        "privateEndpointConnections": [
            {
                "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc1/privateEndpointConnections/test.3d321801-7cb1-4586-afa7-deee7ab88744",
                "name": "test.3d321801-7cb1-4586-afa7-deee7ab88744",
                "type": "Microsoft.Storage/storageAccounts/privateEndpointConnections",
            }
        ],
        "publicNetworkAccess": "Enabled"
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc2',
        'location': 'eastus',
        'name': 'acc2',
        'tags': {},
        "privateEndpointConnections": [],
        "publicNetworkAccess": "Disabled"
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc3',
        'location': 'eastus',
        'name': 'acc3',
        'tags': {},
        "privateEndpointConnections": [],
        "publicNetworkAccess": "Enabled"
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc4',
        'location': 'eastus',
        'name': 'acc4',
        'tags': {},
        "privateEndpointConnections": [],
        "publicNetworkAccess": "Enabled",
        "networkAcls": {
            "defaultAction": "Deny",
            "ipRules": [
                {
                    "value": "192.168.1.0/24",
                    "action": "Allow"
                }
            ],
            "virtualNetworkRules": []
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc5',
        'location': 'eastus',
        'name': 'acc5',
        'tags': {},
        "privateEndpointConnections": [],
        "publicNetworkAccess": "Enabled",
        "networkAcls": {
            "defaultAction": "Allow",
            "ipRules": [],
            "virtualNetworkRules": []
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc6',
        'location': 'eastus',
        'name': 'acc6',
        'tags': {},
        "privateEndpointConnections": [],
        // publicNetworkAccess property missing
        "networkAcls": {
            "defaultAction": "Allow",
            "ipRules": [],
            "virtualNetworkRules": []
        }
    }
];

const createCache = (storageAccounts) => {
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    data: storageAccounts
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        storageAccounts: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('storageAccountPrivateEndpoint', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([]);
            storageAccountPrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createErrorCache();
            storageAccountPrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if private endpoint configured', function(done) {
            const cache = createCache([storageAccounts[0]]);
            storageAccountPrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Private endpoints are configured for the storage account');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if public network access is disabled', function(done) {
            const cache = createCache([storageAccounts[1]]);
            storageAccountPrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage account is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if public network access is enabled without network restrictions', function(done) {
            const cache = createCache([storageAccounts[2]]);
            storageAccountPrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage account is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if public network access is enabled with network restrictions when check_selected_networks is true', function(done) {
            const cache = createCache([storageAccounts[3]]);
            const settings = { check_selected_networks: true };
            storageAccountPrivateEndpoint.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage account is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if public network access is enabled without sufficient network restrictions when check_selected_networks is true', function(done) {
            const cache = createCache([storageAccounts[4]]);
            const settings = { check_selected_networks: true };
            storageAccountPrivateEndpoint.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage account is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if public network access is enabled regardless of network restrictions when check_selected_networks is false', function(done) {
            const cache = createCache([storageAccounts[3]]);
            const settings = { check_selected_networks: false };
            storageAccountPrivateEndpoint.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage account is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if publicNetworkAccess is missing but networkAcls defaultAction is Allow', function(done) {
            const cache = createCache([storageAccounts[5]]);
            storageAccountPrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage account is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});