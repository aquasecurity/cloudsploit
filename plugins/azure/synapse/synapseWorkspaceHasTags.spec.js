var expect = require('chai').expect;
var synapseWorkspaceHasTags = require('./synapseWorkspaceHasTags');

const workspaces = [
    {
        type: "Microsoft.Synapse/workspaces",
        id: "/subscriptions/123/resourceGroups/rsgrp/providers/Microsoft.Synapse/workspaces/test",
        location: "eastus",
        name: "test",
        "tags": {
            "key": "value"
        }
    },
    {
        type: "Microsoft.Synapse/workspaces",
        id: "/subscriptions/123/resourceGroups/rsgrp/providers/Microsoft.Synapse/workspaces/test",
        location: "eastus",
        name: "test",
        "tags": {}
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

describe('synapseWorkspaceHasTags', function () {
    describe('run', function () {

        it('should give a passing result if no Synapse workspaces are found', function (done) {
            const cache = createCache([], null);
            synapseWorkspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Synapse workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Synapse workspaces', function (done) {
            const cache = createCache(null, ['error']);
            synapseWorkspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Synapse workspaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if workspace has tags', function (done) {
            const cache = createCache([workspaces[0]], null);
            synapseWorkspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Synapse workspace has tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if workspace does not have tags', function (done) {
            const cache = createCache([workspaces[1]], null);
            synapseWorkspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Synapse workspace does not have tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});