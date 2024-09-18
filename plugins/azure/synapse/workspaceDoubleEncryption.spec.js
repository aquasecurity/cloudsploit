var expect = require('chai').expect;
var workspaceDoubleEncryption = require('./workspaceDoubleEncryption');

const workspaces = [
    {
        type: "Microsoft.Synapse/workspaces",
        id: "/subscriptions/123/resourceGroups/rsgrp/providers/Microsoft.Synapse/workspaces/test",
        location: "eastus",
        name: "test",
        encryption: {
            doubleEncryptionEnabled: false
        }
    },
    {
        type: "Microsoft.Synapse/workspaces",
        id: "/subscriptions/123/resourceGroups/rsgrp/providers/Microsoft.Synapse/workspaces/test",
        location: "eastus",
        name: "test",
        encryption: {
            cmk: {
                kekIdentity: {
                    useSystemAssignedIdentity: true,
                },
                key: {
                    name: "default",
                    keyVaultUrl: "https://test-key-0011.vault.azure.net/keys/test-key",
                },
            },
            doubleEncryptionEnabled: true,
        } 
    },
];


const createCache = (workspaces, err) => {

    return {
        synapse: {
            listWorkspaces: {
                'eastus': {
                    data: workspaces,
                    err: err
                }
            }
        }
    };
};

describe('workspaceDoubleEncryption', function () {
    describe('run', function () {

        it('should give a passing result if no Synapse workspaces are found', function (done) {
            const cache = createCache([], null);
            workspaceDoubleEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Synapse workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Synapse workspaces', function (done) {
            const cache = createCache(null, ['error']);
            workspaceDoubleEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Synapse workspaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if workspace has double encryption enabled', function (done) {
            const cache = createCache([workspaces[1]], null);
            workspaceDoubleEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Synapse workspace has double encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if workspace does not have double encryption enabled', function (done) {
            const cache = createCache([workspaces[0]], null);
            workspaceDoubleEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Synapse workspace does not have double encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});