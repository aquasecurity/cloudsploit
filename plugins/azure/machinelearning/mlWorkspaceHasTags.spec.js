var expect = require('chai').expect;
var workspaceHasTags = require('./mlWorkspaceHasTags');

const workspaces = [
    {
        "id": "/subscriptions/12345667/resourceGroups/test/providers/Microsoft.MachineLearningServices/workspaces/test1",
        "name": "test",
        "type": "Microsoft.MachineLearningServices/workspaces",
        "identity": {
            "type": "SystemAssigned"
        },
        "tags": {
            "test": "test"
        }
    
      },
      {
        "id": "/subscriptions/12345667/resourceGroups/test/providers/Microsoft.MachineLearningServices/workspaces/test1",
        "name": "test",
        "type": "Microsoft.MachineLearningServices/workspaces",
    
      },
];

const createCache = (workspaces) => {
    return {
        machineLearning: {
            listWorkspaces: {
                'eastus': {
                    data: workspaces
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        machineLearning: {
            listWorkspaces: {
                'eastus': {}
            }
        }
    };
};

describe('workspaceHasTags', function() {
    describe('run', function() {
        it('should give passing result if no Machine Learning workspace found', function(done) {
            const cache = createCache([]);
            workspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Machine Learning workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Machine Learning workspaces', function(done) {            
        const cache = createErrorCache();
            workspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Machine Learning workspaces: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if Machine Learning workspace has tags associated', function(done) {
            const cache = createCache([workspaces[0]]);
            workspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Machine Learning workspace has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Machine Learning workspace does not have tags associated', function(done) {
            const cache = createCache([workspaces[1]]);
            workspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Machine Learning workspace does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});