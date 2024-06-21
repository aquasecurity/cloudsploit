var expect = require('chai').expect;
var namespaceHasTags = require('./namespaceHasTags.js');

const namespaces = [
    {
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test',
        name: 'test',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        tags: {}
    },
    {
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test',
        name: 'test2',
        type: 'Microsoft.ServiceBus/Namespaces',
        tags:{
             abc: "1234"
        }
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

describe('namespaceHasTags', function () {
    describe('run', function () {

        it('should give a passing result if no Service Bus namespaces are found', function (done) {
            const cache = createCache([], null);
            namespaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Service Bus namespaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Service Bus namespaces', function (done) {
            const cache = createCache(null, ['error']);
            namespaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Service Bus namespaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    
        it('should give passing result if Service Bus namespace has tags', function (done) {
            const cache = createCache([namespaces[1]], null);
            namespaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service Bus Namespace has tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Service Bus namespace does not have tags', function (done) {
            const cache = createCache([namespaces[0]], null);
            namespaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Service Bus Namespace does not have tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});