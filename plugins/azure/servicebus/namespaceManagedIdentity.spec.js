var expect = require('chai').expect;
var namespaceManagedIdentity = require('./namespaceManagedIdentity');

const namespaces = [
    {
        sku: { name: 'Premium', tier: 'Premium', capacity: 1 },
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test',
        name: 'test',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        publicNetworkAccess: 'Enabled',
        disableLocalAuth: false,
        provisioningState: 'Succeeded',
        status: 'Active'
    },
    {
        sku: { name: 'Premium', tier: 'Premium', capacity: 1 },
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test2',
        name: 'test2',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        publicNetworkAccess: 'Disabled',
        disableLocalAuth: true,
        provisioningState: 'Succeeded',
        status: 'Active',
        identity : {
            "type": 'SystemAssigned'
        },
        encryption: {
            keySource: 'Microsoft.KeyVault',
            requireInfrastructureEncryption: false
          },
    },
    {
        sku: { name: 'Basic', tier: 'Basic' },
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test3',
        name: 'test2',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        publicNetworkAccess: 'Enabled',
        disableLocalAuth: true,
        provisioningState: 'Succeeded',
        status: 'Active'
    },
];


const createCache = (namespaces, err) => {

    return {
        serviceBus: {
            listNamespacesBySubscription: {
                'eastus': {
                    data: namespaces,
                    err: err
                }
            }
        }
    };
};

describe('namespaceManagedIdentity', function () {
    describe('run', function () {

        it('should give a passing result if no Service Bus namespaces are found', function (done) {
            const cache = createCache([], null);
            namespaceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Service Bus namespaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Service Bus namespaces', function (done) {
            const cache = createCache(null, ['error']);
            namespaceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Service Bus namespaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    
        it('should give passing result if namespace is not using premium tier', function (done) {
            const cache = createCache([namespaces[2]], null);
            namespaceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service Bus Namespace is not a premium namespace');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if namespace has managed identity', function (done) {
            const cache = createCache([namespaces[1]], null);
            namespaceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service bus namespace has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if namespace doesnot have managed identity', function (done) {
            const cache = createCache([namespaces[0]], null);
            namespaceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Service bus namespace does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});