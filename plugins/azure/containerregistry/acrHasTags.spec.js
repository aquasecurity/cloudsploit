var expect = require('chai').expect;
var acrHasTags = require('./acrHasTags');

const acr = [
    {
        "name": 'test-gateway',
        "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providersMicrosoft.ContainerRegistry/registries/giotestacr",
        "type": "Microsoft.ContainerRegistry/registries",
        "tags": { "key": "value" },
        "location": "eastus",
    },
    {
       "name": 'test-gateway',
        "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providersMicrosoft.ContainerRegistry/registries/giotestacr",
        "type": "Microsoft.ContainerRegistry/registries",
        "tags": {},
        "location": "eastus",
    }
];

const createCache = (cr) => {
    return {
        registries: {
            list: {
                'eastus': {
                    data: cr
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        registries: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('acrHasTags', function() {
    describe('run', function() {
        it('should give passing result if no container registery found', function(done) {
            const cache = createCache([]);
            acrHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Container registries found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if container registery does not have tags associated', function(done) {
            const cache = createCache([acr[1]]);
            acrHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Conatiner Registry does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for container registery', function(done) {
            const cache = createErrorCache();
            acrHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Container registries:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if container registery has tags associated', function(done) {
            const cache = createCache([acr[0]]);
            acrHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Conatiner Registry has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 