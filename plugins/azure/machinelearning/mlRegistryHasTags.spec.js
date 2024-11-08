var expect = require('chai').expect;
var mlRegistryHasTags = require('./mlRegistryHasTags');

const registry = [
    {
        "id": "/subscriptions/12345667/resourceGroups/test/providers/Microsoft.MachineLearningServices/registries/test1",
        "name": "test",
        "type": "Microsoft.MachineLearningServices/registries",
        "tags": {
            "test": "test"
        },
        "publicNetworkAccess" : "Disabled"
    
      },
      {
        "id": "/subscriptions/12345667/resourceGroups/test/providers/Microsoft.MachineLearningServices/registries/test1",
        "name": "test",
        "type": "Microsoft.MachineLearningServices/registries",
        "publicNetworkAccess" : "Enabled"
      },
     
];

const createCache = (registries) => {
    return {
        machineLearning: {
            listRegistries: {
                'eastus': {
                    data: registries
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        machineLearning: {
            listRegistries: {
                'eastus': {}
            }
        }
    };
};

describe('mlRegistryHasTags', function() {
    describe('run', function() {
        it('should give passing result if no Machine Learning registry found', function(done) {
            const cache = createCache([]);
            mlRegistryHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Machine Learning registries found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Machine Learning registry', function(done) {      
            const cache = createErrorCache();
            mlRegistryHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Machine Learning registries: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if Machine Learning registry has tags associated', function(done) {
            const cache = createCache([registry[0]]);
            mlRegistryHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Machine Learning registry has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Machine Learning registry does not have tags associated', function(done) {
            const cache = createCache([registry[1]]);
            mlRegistryHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Machine Learning registry does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});