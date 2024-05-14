var expect = require('chai').expect;
var workspaceManagedIdentity = require('./workspaceManagedIdentity');

const workspaces = [
    {
        "id": "/subscriptions/12345667/resourceGroups/test/providers/Microsoft.MachineLearningServices/workspaces/test1",
        "name": "test",
        "type": "Microsoft.MachineLearningServices/workspaces",
        "identity": {
            "type": "SystemAssigned"
        }
    
      },
      {
        "id": "/subscriptions/12345667/resourceGroups/test/providers/Microsoft.MachineLearningServices/workspaces/test1",
        "name": "test",
        "type": "Microsoft.MachineLearningServices/workspaces",
        "identity": {
            "type": "None"
        }
      },
];

const createCache = (workspace) => {
    return {
        machineLearning: {
            listWorkspaces: {
                'eastus': {
                    data: workspace
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

describe('workspaceManagedIdentity', function() {
    describe('run', function() {
        it('should give passing result if no existing Machine Learning workspace found', function(done) {
            const cache = createCache([]);
            workspaceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Machine Learning workspace found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Machine Learning workspaces', function(done) {
            const cache = createErrorCache();
            workspaceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Machine Learning workspaces: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if Machine Learning workspace has managed identity enabled', function(done) {
            const cache = createCache([workspaces[0]]);
            workspaceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Machine Learning workspace has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Machine Learning workspace does not have managed identity enabled', function(done) {
            const cache = createCache([workspaces[1]]);
            workspaceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Machine Learning workspace does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});