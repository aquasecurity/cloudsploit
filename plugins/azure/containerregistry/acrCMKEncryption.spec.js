var expect = require('chai').expect;
var acrCMKEncryption = require('./acrCMKEncryption');

const acr = [
    {
        "name": 'test-gateway',
        "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providersMicrosoft.ContainerRegistry/registries/giotestacr",
        "type": "Microsoft.ContainerRegistry/registries",
        "tags": { "key": "value" },
        "location": "eastus",
        "encryption": { "status": "enabled" },
    },
    {
       "name": 'test-gateway',
        "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providersMicrosoft.ContainerRegistry/registries/giotestacr",
        "type": "Microsoft.ContainerRegistry/registries",
        "tags": {},
        "location": "eastus",
        "encryption": { "status": "disabled" },
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

describe('acrCMKEncryption', function() {
    describe('run', function() {
        it('should give passing result if no container registery found', function(done) {
            const cache = createCache([]);
            acrCMKEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Container registries found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if container registry does not have cmk encryption enabled', function(done) {
            const cache = createCache([acr[1]]);
            acrCMKEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Container Registry does not have CMK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for container registery', function(done) {
            const cache = createErrorCache();
            acrCMKEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Container registries:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if container registry have cmk encryption enabled', function(done) {
            const cache = createCache([acr[0]]);
            acrCMKEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Container Registry has CMK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 