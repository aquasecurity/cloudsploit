var expect = require('chai').expect;
var mlWorkspaceCMKEncrypted = require('./mlWorkspaceCMKEncrypted');

const workspaces = [
    {
        "id": "/subscriptions/12345667/resourceGroups/test/providers/Microsoft.MachineLearningServices/workspaces/test1",
        "name": "test",
        "type": "Microsoft.MachineLearningServices/workspaces",
        "encryption": {
            "keyVaultProperties": {
                "keyIdentifier": "https://dummy.vault.azure.net/keys/test2/9e34232342342343242343",
                "identityClientId": null,
                "keyVaultArmId": "/subscriptions/12345667/resourceGroups/test1223/providers/Microsoft.KeyVault/vaults/dummy"
              },
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

describe('mlWorkspaceCMKEncrypted', function() {
    describe('run', function() {
        it('should give passing result if no Machine Learning workspace found', function(done) {
            const cache = createCache([]);
            mlWorkspaceCMKEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Machine Learning workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Machine Learning workspaces', function(done) {            
        const cache = createErrorCache();
        mlWorkspaceCMKEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Machine Learning workspaces: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if Machine Learning workspace is not encrypted using CMK', function(done) {
            const cache = createCache([workspaces[0]]);
            mlWorkspaceCMKEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Machine Learning workspace is encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Machine Learning workspace is not CMK encrypted', function(done) {
            const cache = createCache([workspaces[1]]);
            mlWorkspaceCMKEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Machine Learning workspace is not encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});